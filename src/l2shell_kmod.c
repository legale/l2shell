/* l2shell_kmod.c - kernel module transport for L2 shell
 * Init-trigger: listens on all interfaces for CLIENT_SIGNATURE frames.
 * On first payload from a client, launches the provided command via
 * call_usermodehelper(). No /dev interface is exposed; the launched
 * userspace helper handles IO (e.g., reverse shell).
 */

#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#define ETHER_TYPE_CUSTOM 0x88B5
#define CLIENT_SIGNATURE 0xAABBCCDDu
#define SERVER_SIGNATURE 0xDDCCBBAAu
#define MAX_PAYLOAD_SIZE 1024
#define PACKET_DEDUP_CACHE 32
#define PACKET_DEDUP_WINDOW_NS (5 * 1000 * 1000ULL)

#include "hello_proto.h"

struct __attribute__((packed)) packh {
    struct ethhdr eth;
    __be32 signature;
    __be32 payload_size;
    __be32 crc;
};

struct __attribute__((packed)) pack {
    struct packh h;
    u8 payload[MAX_PAYLOAD_SIZE];
};

struct fp {
    u8 mac[ETH_ALEN];
    u32 crc;
    u32 psize;
    u32 sig;
    ktime_t ts;
    bool valid;
};

struct dedup_cache {
    struct fp e[PACKET_DEDUP_CACHE];
    size_t cur;
};

static struct {
    spinlock_t launch_lock;
    bool launch_pending;
    struct work_struct launch_work;
    char cmd_buf[MAX_PAYLOAD_SIZE + 1];
    struct dedup_cache dc;
    struct net_device *dev;
    u8 cli_mac[ETH_ALEN];
    bool have_cli;
    bool capture_enabled;
} g;

#define l2sh_info(fmt, ...) pr_info("l2sh: " fmt, ##__VA_ARGS__)

static void dedup_init(struct dedup_cache *dc) {
    memset(dc, 0, sizeof(*dc));
}

static size_t store_spawn_cmd(const u8 *payload, size_t len, const hello_view_t *hello) {
    const u8 *cmd = payload;
    size_t copy_len = len;

    if (!payload || !len)
        return 0;

    if (hello && hello->have_spawn && hello->spawn_len > 0 && hello->spawn_len < sizeof(g.cmd_buf)) {
        cmd = hello->spawn_cmd;
        copy_len = hello->spawn_len;
    } else if (copy_len >= sizeof(g.cmd_buf)) {
        copy_len = sizeof(g.cmd_buf) - 1;
    }

    memcpy(g.cmd_buf, cmd, copy_len);
    g.cmd_buf[copy_len] = '\0';
    return copy_len;
}

static void disable_capture(void);
static void enable_capture(void);

static int build_server_packet(struct pack *pkt, const u8 *src_mac, const u8 *dst_mac,
                               const u8 *payload, size_t payload_len) {
    size_t frame_len;
    u32 crc;

    if (!pkt || !src_mac || !dst_mac || payload_len > MAX_PAYLOAD_SIZE)
        return -EINVAL;

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->h.eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->h.eth.h_dest, dst_mac, ETH_ALEN);
    pkt->h.eth.h_proto = htons(ETHER_TYPE_CUSTOM);
    pkt->h.signature = cpu_to_be32(SERVER_SIGNATURE);
    pkt->h.payload_size = cpu_to_be32((u32)payload_len);
    pkt->h.crc = 0;

    if (payload_len > 0 && payload)
        memcpy(pkt->payload, payload, payload_len);

    if (payload_len > 0)
        enc_dec(pkt->payload, pkt->payload, zero_key, payload_len);

    frame_len = sizeof(pkt->h) + payload_len;
    crc = csum32((const u8 *)pkt, frame_len);
    pkt->h.crc = cpu_to_be32(crc);

    if (payload_len > 0)
        enc_dec(pkt->payload, pkt->payload, (const u8 *)&pkt->h.crc, payload_len);

    return (int)frame_len;
}

static void send_ready_ack(struct net_device *dev, const u8 dst_mac[ETH_ALEN], const struct hello_view *hello) {
    struct pack pkt;
    struct sk_buff *skb;
    char payload[64];
    size_t payload_len;
    int frame_len;
    int err;
    unsigned long long nonce = 0ULL;
    bool have_nonce = false;

    if (!dev || !dst_mac)
        return;

    if (hello && hello->have_nonce) {
        nonce = hello->nonce;
        have_nonce = true;
        payload_len = scnprintf(payload, sizeof(payload),
                                "ready nonce=%016llx source=kernel\n",
                                nonce);
    } else {
        payload_len = scnprintf(payload, sizeof(payload),
                                "ready source=kernel\n");
    }

    frame_len = build_server_packet(&pkt, dev->dev_addr, dst_mac,
                                    (const u8 *)payload, payload_len);
    if (frame_len < 0)
        return;

    skb = netdev_alloc_skb(dev, frame_len + NET_IP_ALIGN);
    if (!skb)
        return;

    skb_reserve(skb, NET_IP_ALIGN);
    memcpy(skb_put(skb, frame_len), &pkt, frame_len);
    skb->dev = dev;
    skb->protocol = htons(ETHER_TYPE_CUSTOM);

    err = dev_queue_xmit(skb);
    if (err)
        pr_info("l2sh: ready ack tx failed err=%d\n", err);
    else if (have_nonce)
        pr_info("l2sh: ready ack sent nonce=%016llx\n", nonce);
    else
        pr_info("l2sh: ready ack sent without nonce\n");
}

static void dump_frame(const char *tag, const u8 *buf, size_t len) {
    if (!buf || !len) return;
    print_hex_dump(KERN_INFO, tag, DUMP_PREFIX_OFFSET, 16, 1, buf, len, false);
}

static bool dedup_drop(struct dedup_cache *dc, const u8 mac[ETH_ALEN],
                       u32 crc, u32 psize, u32 sig, u64 win_ns) {
    u64 now = ktime_get_ns();
    size_t i;

    for (i = 0; i < PACKET_DEDUP_CACHE; i++) {
        struct fp *f = &dc->e[i];
        if (!f->valid)
            continue;
        if (now > (u64)ktime_to_ns(f->ts) &&
            now - (u64)ktime_to_ns(f->ts) > win_ns) {
            f->valid = false;
            continue;
        }
        if (f->valid && f->crc == crc && f->psize == psize &&
            f->sig == sig && !memcmp(f->mac, mac, ETH_ALEN))
            return true;
    }

    dc->e[dc->cur].valid = true;
    dc->e[dc->cur].crc = crc;
    dc->e[dc->cur].psize = psize;
    dc->e[dc->cur].sig = sig;
    dc->e[dc->cur].ts = ktime_get();
    memcpy(dc->e[dc->cur].mac, mac, ETH_ALEN);
    dc->cur = (dc->cur + 1) % PACKET_DEDUP_CACHE;
    return false;
}

static void exec_server(struct work_struct *work) {
    static char *envp[] = {
        "HOME=/tmp",
        "TERM=xterm-256color",
        NULL};
    char *argv[] = {"/usr/bin/setsid", "/bin/sh", "-c", g.cmd_buf, NULL};
    struct subprocess_info *info;

    pr_info("l2sh: launching command: %s\n", g.cmd_buf);

    info = call_usermodehelper_setup(argv[0], argv, envp,
                                     GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        spin_lock(&g.launch_lock);
        g.launch_pending = false;
        spin_unlock(&g.launch_lock);
        return;
    }

    disable_capture();
    call_usermodehelper_exec(info, UMH_WAIT_PROC);
    enable_capture();

    spin_lock(&g.launch_lock);
    g.launch_pending = false;
    spin_unlock(&g.launch_lock);
}

struct chdr {
    __be32 signature;
    __be32 payload_size;
    __be32 crc;
};

static int l2_rx(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    struct ethhdr *eth;
    struct chdr *h;
    u32 sig, psize, crc_recv, crc_calc;
    int need;
    hello_view_t hello;
    bool hello_ok = false;

    /* we only need our header in the linear area */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct chdr)))) {
        l2sh_info("drop on ifname=%s header truncated\n", dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    eth = eth_hdr(skb);           /* mac header */
    h = (struct chdr *)skb->data; /* our header sits in payload */

    if (unlikely(!eth)) {
        l2sh_info("drop on ifname=%s no ethhdr\n", dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    /* double check ethertype even though we are bound to it */
    if (unlikely(eth->h_proto != htons(ETHER_TYPE_CUSTOM)))
        return NET_RX_SUCCESS;

    sig = be32_to_cpu(h->signature);
    psize = be32_to_cpu(h->payload_size);
    crc_recv = be32_to_cpu(h->crc);

    if (sig != CLIENT_SIGNATURE)
        return NET_RX_SUCCESS;

    if (psize > MAX_PAYLOAD_SIZE) {
        l2sh_info("drop pay_sz=%u ifname=%s (too large)\n",
                  psize,
                  dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    need = (int)sizeof(struct chdr) + (int)psize;
    if (unlikely(!pskb_may_pull(skb, need))) {
        l2sh_info("drop pay_sz=%u ifname=%s (truncated)\n",
                  psize,
                  dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    l2sh_info("frame from ifname=%s src=%pM payload=%u\n",
              dev ? dev->name : "<unknown>",
              eth->h_source,
              psize);

    if (dedup_drop(&g.dc, eth->h_source, crc_recv, psize, sig, PACKET_DEDUP_WINDOW_NS)) {
        l2sh_info("dedup drop src=%pM\n", eth->h_source);
        return NET_RX_SUCCESS;
    }

    /* сначала расшифровываем payload, затем считаем crc так же, как в userland */
    enc_dec((u8 *)(h + 1), (u8 *)(h + 1), (u8 *)&h->crc, psize);

    dump_frame("l2sh: rx frame ", (const u8 *)eth, ETH_HLEN + sizeof(*h) + psize);

    /* вычисляем crc по ethernet-заголовку, нашему заголовку (crc=0) и payload */
    {
        struct chdr hdr_copy = *h;
        hdr_copy.crc = 0;
        crc_calc = csum32((const u8 *)eth, ETH_HLEN);
        crc_calc += csum32((const u8 *)&hdr_copy, sizeof(hdr_copy));
        if (psize > 0)
            crc_calc += csum32((const u8 *)(h + 1), psize);
    }

    if (crc_calc != crc_recv) {
        l2sh_info("crc mismatch src=%pM recv=%u calc=%u\n",
                  eth->h_source, crc_recv, crc_calc);
        return NET_RX_SUCCESS;
    }

    /* вычисляем crc по ethernet-заголовку, нашему заголовку (crc=0) и payload */
    {
        struct chdr hdr_copy = *h;
        hdr_copy.crc = 0;
        crc_calc = csum32((const u8 *)eth, ETH_HLEN);
        crc_calc += csum32((const u8 *)&hdr_copy, sizeof(hdr_copy));
        if (psize > 0)
            crc_calc += csum32((const u8 *)(h + 1), psize);
    }

    if (crc_calc != crc_recv) {
        l2sh_info("crc mismatch src=%pM recv=%u calc=%u\n",
                  eth->h_source, crc_recv, crc_calc);
        return NET_RX_SUCCESS;
    }

    if (psize > 0)
        enc_dec((u8 *)(h + 1), (u8 *)(h + 1), zero_key, psize);

    memset(&hello, 0, sizeof(hello));
    if (psize > 0 && hello_parse((u8 *)(h + 1), (size_t)psize, &hello) == 0)
        hello_ok = true;

    if (!g.have_cli || memcmp(g.cli_mac, eth->h_source, ETH_ALEN)) {
        memcpy(g.cli_mac, eth->h_source, ETH_ALEN);
        rcu_assign_pointer(g.dev, dev);
        g.have_cli = true;
        pr_info("l2sh: tracking client=%pM on ifname=%s\n",
                g.cli_mac,
                dev ? dev->name : "<unknown>");
    }

    if (psize > 0) {
        unsigned long flags;
        bool should_ack = false;
        spin_lock_irqsave(&g.launch_lock, flags);
        if (!g.launch_pending) {
            size_t used = store_spawn_cmd((u8 *)(h + 1), (size_t)psize, hello_ok ? &hello : NULL);
            if (!used) {
                g.cmd_buf[0] = '\0';
                l2sh_info("hello parse failed, empty command\n");
            }
            g.launch_pending = true;
            should_ack = true;
            l2sh_info("command to run src=%pM %s\n", eth->h_source, g.cmd_buf[0] ? g.cmd_buf : "<empty>");
            schedule_work(&g.launch_work);
        } else {
            l2sh_info("command already pending, ignoring new payload\n");
        }
        spin_unlock_irqrestore(&g.launch_lock, flags);

        if (should_ack)
            send_ready_ack(dev, eth->h_source, hello_ok ? &hello : NULL);
    }

    return NET_RX_SUCCESS;
}

static void log_interfaces(void) {
    struct net_device *dev;
    struct net *net = &init_net;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    read_lock(&dev_base_lock);
    for_each_netdev(net, dev) {
        pr_info("l2sh: listening on ifname=%s mac=%pM\n", dev->name, dev->dev_addr);
    }
    read_unlock(&dev_base_lock);
#else
    rcu_read_lock();
    for_each_netdev_rcu(net, dev) {
        pr_info("l2sh: listening on ifname=%s mac=%pM\n", dev->name, dev->dev_addr);
    }
    rcu_read_unlock();
#endif
}

static struct packet_type l2_pt = {
    .type = cpu_to_be16(ETHER_TYPE_CUSTOM),
    .func = l2_rx,
};

static void disable_capture(void) {
    if (!g.capture_enabled)
        return;
    dev_remove_pack(&l2_pt);
    g.capture_enabled = false;
    pr_info("l2sh: capture disabled, handing off to userspace server\n");
}

static void enable_capture(void) {
    if (g.capture_enabled)
        return;
    dev_add_pack(&l2_pt);
    g.capture_enabled = true;
    pr_info("l2sh: capture re-enabled\n");
}

static int __init l2_init(void) {
    memset(&g, 0, sizeof(g));
    spin_lock_init(&g.launch_lock);
    INIT_WORK(&g.launch_work, exec_server);
    dedup_init(&g.dc);

    enable_capture();
    pr_info("l2sh: kernel trigger loaded, ethertype 0x%04x\n", ETHER_TYPE_CUSTOM);
    log_interfaces();
    return 0;
}

static void __exit l2_exit(void) {
    disable_capture();
    flush_work(&g.launch_work);
    pr_info("l2sh: unloaded\n");
}

module_init(l2_init);
module_exit(l2_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("me");
MODULE_DESCRIPTION("L2 shell kernel module");
