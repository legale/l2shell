/* l2shell_kmod.c - kernel module transport for L2 shell
 * exposes /dev/l2sh for userspace io
 * rx: frames with CLIENT_SIGNATURE -> read() from /dev/l2sh
 * tx: write() to /dev/l2sh -> frames with SERVER_SIGNATURE to last client
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/if_ether.h>

#define ETHER_TYPE_CUSTOM 0x88B5
#define CLIENT_SIGNATURE 0xAABBCCDDu
#define SERVER_SIGNATURE 0xDDCCBBAAu
#define MAX_PAYLOAD_SIZE 1024
#define RX_BUF_SZ (64 * 1024)
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

static const u8 bcast_mac[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

static struct {
	/* rx ring for /dev/l2sh reads */
	u8 *rx;
	size_t rx_head;
	size_t rx_tail;
	spinlock_t rx_lock;
	wait_queue_head_t rx_wq;

	/* last client endpoint */
	struct net_device *dev;
	u8 cli_mac[ETH_ALEN];
	bool have_cli;

	/* dedup */
	struct dedup_cache dc;

	/* miscdev open state */
	atomic_t open_cnt;
} g;

static inline size_t rx_avail(void)
{
	return g.rx_head - g.rx_tail;
}

static inline size_t rx_space(void)
{
	return RX_BUF_SZ - rx_avail();
}

static void enc_dec(const u8 *in, u8 *out, const u8 *key, size_t len)
{
	static const u8 km[4] = {4,1,2,3};
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

static u32 csum32(const u8 *p, size_t n)
{
	u32 s = 0;
	size_t i;
	for (i = 0; i < n; i++)
		s += p[i];
	return s;
}

static void dedup_init(struct dedup_cache *dc)
{
	memset(dc, 0, sizeof(*dc));
}

static bool dedup_drop(struct dedup_cache *dc, const u8 mac[ETH_ALEN],
		       u32 crc, u32 psize, u32 sig, u64 win_ns)
{
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
	{
		struct fp *s = &dc->e[dc->cur];
		memcpy(s->mac, mac, ETH_ALEN);
		s->crc = crc;
		s->psize = psize;
		s->sig = sig;
		s->ts = ktime_get();
		s->valid = true;
		dc->cur = (dc->cur + 1) % PACKET_DEDUP_CACHE;
	}
	return false;
}

static int push_rx(const u8 *data, size_t len)
{
	unsigned long f;
	size_t space, off, ch1, ch2;

	if (!len)
		return 0;

	spin_lock_irqsave(&g.rx_lock, f);
	space = rx_space();
	if (len > space) {
		spin_unlock_irqrestore(&g.rx_lock, f);
		return -ENOSPC;
	}

	off = g.rx_head % RX_BUF_SZ;
	ch1 = min(len, RX_BUF_SZ - off);
	memcpy(g.rx + off, data, ch1);
	ch2 = len - ch1;
	if (ch2)
		memcpy(g.rx, data + ch1, ch2);
	g.rx_head += len;
	spin_unlock_irqrestore(&g.rx_lock, f);

	wake_up_interruptible(&g.rx_wq);
	return 0;
}

static ssize_t pop_rx(u8 __user *ubuf, size_t len, bool nonblock)
{
	unsigned long f;
	size_t avail, off, ch1, ch2;
	int ret;

retry:
	spin_lock_irqsave(&g.rx_lock, f);
	avail = rx_avail();
	if (!avail) {
		spin_unlock_irqrestore(&g.rx_lock, f);
		if (nonblock)
			return -EAGAIN;
		ret = wait_event_interruptible(g.rx_wq, rx_avail() > 0);
		if (ret)
			return ret;
		goto retry;
	}

	len = min(len, avail);
	off = g.rx_tail % RX_BUF_SZ;
	ch1 = min(len, RX_BUF_SZ - off);
	if (copy_to_user(ubuf, g.rx + off, ch1)) {
		spin_unlock_irqrestore(&g.rx_lock, f);
		return -EFAULT;
	}
	ch2 = len - ch1;
	if (ch2 && copy_to_user(ubuf + ch1, g.rx, ch2)) {
		spin_unlock_irqrestore(&g.rx_lock, f);
		return -EFAULT;
	}
	g.rx_tail += len;
	spin_unlock_irqrestore(&g.rx_lock, f);
	return len;
}

/* build + tx one server frame to last client */
static int tx_payload(const u8 *data, size_t len)
{
	struct net_device *dev;
	struct sk_buff *skb;
	struct pack *p;
	size_t frame_len;
	int err = 0;

	if (!g.have_cli)
		return -ENOTCONN;
	if (!len || len > MAX_PAYLOAD_SIZE)
		return -EINVAL;

	rcu_read_lock();
	dev = rcu_dereference(g.dev);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}
	dev_hold(dev);
	rcu_read_unlock();

	frame_len = sizeof(struct packh) + len;

	skb = alloc_skb(ETH_HLEN + frame_len + NET_IP_ALIGN, GFP_KERNEL);
	if (!skb) {
		dev_put(dev);
		return -ENOMEM;
	}
	skb_reserve(skb, NET_IP_ALIGN);
	p = (struct pack *)skb_put(skb, frame_len);

	ether_addr_copy(p->h.eth.h_source, dev->dev_addr);
	ether_addr_copy(p->h.eth.h_dest, g.cli_mac);
	p->h.eth.h_proto = htons(ETHER_TYPE_CUSTOM);

	p->h.signature = cpu_to_be32(SERVER_SIGNATURE);
	p->h.payload_size = cpu_to_be32((u32)len);
	p->h.crc = cpu_to_be32(0);

	memcpy(p->payload, data, len);
	{
		u32 crc;
		crc = csum32((u8 *)p, frame_len);
		p->h.crc = cpu_to_be32(crc);
		enc_dec(p->payload, p->payload, (u8 *)&p->h.crc, len);
	}

	skb->dev = dev;
	skb->protocol = htons(ETHER_TYPE_CUSTOM);
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	err = dev_queue_xmit(skb);
	if (err)
		pr_err("l2sh: dev_queue_xmit err=%d\n", err);

	dev_put(dev);
	return err ? -EIO : 0;
}

static int l2_rx(struct sk_buff *skb, struct net_device *dev,
		 struct packet_type *pt, struct net_device *orig_dev)
{
	struct pack *p;
	u32 sig, psize, crc_recv, crc_calc;
	int need;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct packh))))
		goto out;

	p = (struct pack *)skb_mac_header(skb);
	if (unlikely(p->h.eth.h_proto != htons(ETHER_TYPE_CUSTOM)))
		goto out;

	sig = be32_to_cpu(p->h.signature);
	psize = be32_to_cpu(p->h.payload_size);
	crc_recv = be32_to_cpu(p->h.crc);

	if (sig != CLIENT_SIGNATURE)
		goto out;
	if (psize > MAX_PAYLOAD_SIZE)
		goto out;
	need = sizeof(struct packh) + (int)psize;
	if (unlikely(!pskb_may_pull(skb, need)))
		goto out;

	/* dedup */
	if (dedup_drop(&g.dc, p->h.eth.h_source, crc_recv, psize, sig, PACKET_DEDUP_WINDOW_NS))
		goto out;

	/* decrypt */
	enc_dec(p->payload, p->payload, (u8 *)&p->h.crc, psize);

	/* crc check */
	{
		u32 old = p->h.crc;
		p->h.crc = cpu_to_be32(0);
		crc_calc = csum32((u8 *)p, need);
		p->h.crc = old;
	}
	if (crc_calc != crc_recv)
		goto out;

	/* remember last client endpoint */
	if (!g.have_cli || memcmp(g.cli_mac, p->h.eth.h_source, ETH_ALEN)) {
		memcpy(g.cli_mac, p->h.eth.h_source, ETH_ALEN);
		rcu_assign_pointer(g.dev, dev);
		g.have_cli = true;
	}

	/* push to rx ring */
	if (push_rx(p->payload, psize) != 0)
		; /* drop silently */

out:
	return NET_RX_SUCCESS;
}

static struct packet_type l2_pt = {
	.type = cpu_to_be16(ETHER_TYPE_CUSTOM),
	.func = l2_rx,
};

static ssize_t l2_read(struct file *f, char __user *ubuf, size_t len, loff_t *ppos)
{
	bool nb = f->f_flags & O_NONBLOCK;
	return pop_rx((u8 __user *)ubuf, len, nb);
}

static ssize_t l2_write(struct file *f, const char __user *ubuf, size_t len, loff_t *ppos)
{
	u8 *kbuf;
	int ret;

	if (!len)
		return 0;
	if (len > MAX_PAYLOAD_SIZE)
		return -EMSGSIZE;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, ubuf, len)) {
		kfree(kbuf);
		return -EFAULT;
	}
	ret = tx_payload(kbuf, len);
	kfree(kbuf);
	if (ret)
		return ret;
	return len;
}

static int l2_open(struct inode *ino, struct file *f)
{
	if (atomic_inc_return(&g.open_cnt) > 1) {
		atomic_dec(&g.open_cnt);
		return -EBUSY;
	}
	return 0;
}

static int l2_release(struct inode *ino, struct file *f)
{
	atomic_dec(&g.open_cnt);
	return 0;
}

static const struct file_operations l2_fops = {
	.owner = THIS_MODULE,
	.read = l2_read,
	.write = l2_write,
	.open = l2_open,
	.release = l2_release,
	.llseek = no_llseek,
};

static struct miscdevice l2_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "l2sh",
	.fops = &l2_fops,
	.mode = 0600,
};

static int __init l2_init(void)
{
	int ret;

	memset(&g, 0, sizeof(g));
	g.rx = vzalloc(RX_BUF_SZ);
	if (!g.rx)
		return -ENOMEM;
	spin_lock_init(&g.rx_lock);
	init_waitqueue_head(&g.rx_wq);
	atomic_set(&g.open_cnt, 0);
	dedup_init(&g.dc);

	ret = misc_register(&l2_misc);
	if (ret) {
		vfree(g.rx);
		return ret;
	}
	dev_add_pack(&l2_pt);
	pr_info("l2sh: loaded, /dev/l2sh ready, ethertype 0x%04x\n", ETHER_TYPE_CUSTOM);
	return 0;
}

static void __exit l2_exit(void)
{
	dev_remove_pack(&l2_pt);
	misc_deregister(&l2_misc);
	if (g.dev)
		rcu_assign_pointer(g.dev, NULL);
	if (g.rx)
		vfree(g.rx);
	pr_info("l2sh: unloaded\n");
}

module_init(l2_init);
module_exit(l2_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("L2 shell kernel transport");
