#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/fcntl.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/mount.h>
#include <xen/events.h>
#include <asm/xen/page.h>
#include <linux/vmalloc.h>

#include <net/v4v.h>

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0) ) /* sk_add_backlog */
# define v4v_sk_add_backlog(sk, skb) sk_add_backlog(sk, skb)
#else
# define v4v_sk_add_backlog(sk, skb) sk_add_backlog(sk, skb, sk->sk_rcvbuf)
#endif

/* Must be greater than or equal to sizeof (struct v4v_addr) */
#define V4V_SKB_HEADROOM 16

/*
 * Rings
 */
static HLIST_HEAD(sk_list);
static DEFINE_RWLOCK(sk_lock);

static int v4v_port_inuse(uint32_t port)
{
	struct sock *sk;
	int rc = 0;

	read_lock(&sk_lock);

	sk_for_each(sk, &sk_list) {
		struct v4v_sock *v = v4v_sk(sk);

		if (v->ring->id.addr.port == port) {
			rc = 1;
			break;
		}
	}

	read_unlock(&sk_lock);
	return rc;
}

static int v4v_id_inuse(struct v4v_ring_id *id)
{
	struct sock *sk;
	int rc = 0;

	read_lock(&sk_lock);

	sk_for_each(sk, &sk_list) {
		struct v4v_sock *v = v4v_sk(sk);

		if (!memcmp(&v->ring->id, id, sizeof (*id))) {
			rc = 1;
			break;
		}
	}

	read_unlock(&sk_lock);
	return rc;
}

static uint32_t v4v_port_alloc(void)
{
	uint32_t port;

	do {
		port = prandom_u32() | 0x80000000U;
	} while ( port > 0xf0000000U  || v4v_port_inuse(port));

	return port;
}

static void v4v_unregister_ring(struct v4v_sock *v)
{
	int rc;

	rc = HYPERVISOR_v4v_op(V4VOP_unregister_ring, v->ring, v->pfns,
			       NULL, 0, 0);
	if (rc)
		return;

	vfree(v->ring);
	v->ring = NULL;
	kfree(v->pfns);
	v->pfns = NULL;
}

static int v4v_register_ring(struct v4v_sock *v, struct v4v_address *addr,
			     size_t ring_len)
{
	size_t len = ring_len + sizeof (struct v4v_ring);
	size_t npages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	int rc;
	size_t i;
	unsigned char *p;
	struct v4v_ring_id id;

	if (v->ring || v->pfns)
		return -EINVAL;

	id.addr.port = addr->port;
	id.addr.domain = V4V_DOMID_ANY;
	id.partner = addr->domain;
	if (!addr->port)
		id.addr.port = v4v_port_alloc();
	if (v4v_id_inuse(&id))
		return -EADDRINUSE;

	rc = -ENOMEM;
	v->ring = vmalloc(len);
	if (!v->ring)
		goto fail_vmalloc;
	memset(v->ring, 0, len);

	v->ring->magic = V4V_RING_MAGIC;
	v->ring->len = ring_len;
	v->ring->rx_ptr = v->ring->tx_ptr = 0;
	v->ring->id = id;

	v->pfns = kmalloc(sizeof (struct v4v_pfn_list) +
			  npages * sizeof (v->pfns->pages[0]),
			  GFP_KERNEL);
	if (!v->pfns)
		goto fail_kmalloc;

	v->pfns->magic = V4V_PFN_LIST_MAGIC;
	v->pfns->npage = npages;

	p = (unsigned char *)v->ring;
	for (i = 0; i < npages; i++)
		v->pfns->pages[i] =
		    pfn_to_mfn(vmalloc_to_pfn(p + i * PAGE_SIZE));

	rc = HYPERVISOR_v4v_op(V4VOP_register_ring, v->ring, v->pfns,
			       NULL, 0, 0);
	if (rc)
		goto fail_register;

	addr->port = v->ring->id.addr.port;
	addr->domain = v->ring->id.addr.domain;

	return 0;
fail_register:
	kfree(v->pfns);
	v->pfns = NULL;
fail_kmalloc:
	vfree(v->ring);
	v->ring = NULL;
fail_vmalloc:
	return rc;
}

/*
 * Tasklet
 */
static struct sk_buff *v4v_skb_from_ring(volatile struct v4v_ring *ring)
{
	size_t avail = v4v_ring_data_avail(ring);
	struct v4v_ring_msghdr *mh;
	size_t len, chunk;
	struct sk_buff *skb;
	uint32_t rx_ptr = ring->rx_ptr;

	/* Guaranteed to never wrap thanks to ring alignment rule */
	mh = v4v_ring_peek(ring, sizeof (*mh));
	if (!mh)
		return NULL;

	len = mh->len;

	/* Need more bytes */
	if (avail < len)
		return NULL;

	rx_ptr += sizeof (*mh);
	len -= sizeof (*mh);

	skb = alloc_skb(len + V4V_SKB_HEADROOM, GFP_ATOMIC);
	if (!skb)
		return NULL;
	skb_reserve(skb, V4V_SKB_HEADROOM);

	chunk = ring->len - rx_ptr;
	if (len > chunk) {
		memcpy(skb_put(skb, chunk), (void *)&ring->ring[rx_ptr], chunk);
		len -= chunk;
		rx_ptr = 0;
	}

	if (len) {
		memcpy(skb_put(skb, len), (void *)&ring->ring[rx_ptr], len);
		rx_ptr += V4V_ROUNDUP(len);

		if (rx_ptr == ring->len)
			rx_ptr = 0;
	}

	mb();
	ring->rx_ptr = rx_ptr;

	return skb;
}

static inline bool may_queue(const struct sock *sk)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize < sk->sk_rcvbuf;
}

static int v4v_xmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct v4v_addr *dst = (void *)skb->data;
	struct v4v_sock *v = v4v_sk(sk);
	unsigned char *p;
	size_t len;
	uint32_t proto;

	if (sk->sk_type == SOCK_STREAM)
		proto = V4V_PROTO_STREAM;
	else if (sk->sk_type == SOCK_DGRAM)
		proto = V4V_PROTO_DGRAM;
	else
		return -EINVAL;

	/* Check there's at least 1 byte to xmit */
	if (skb->len <=  sizeof (*dst))
		return -EINVAL;

	p = skb->data + sizeof (*dst);
	len = skb->len - sizeof (*dst);

	if (v->parent)
		v = v4v_sk(v->parent);

	return HYPERVISOR_v4v_op(V4VOP_send, &v->ring->id.addr,
					     dst,
					     p, len,
					     proto);
}

/* Grabs a reference and lock the returned sock */
static struct sock *v4v_conn_lookup(struct sock *parent,
				    struct v4v_addr *addr)
{
	struct sock *sk, *ret = NULL;
	struct v4v_sock *p = v4v_sk(parent);

	read_lock_bh(&p->conn_lock);
	sk_for_each(sk, &p->connections) {
		struct v4v_sock *v = v4v_sk(sk);

		if (!memcmp(addr, &v->peer, sizeof (*addr))) {
		    sock_hold(sk);
		    ret = sk;
		    break;
		}
	}
	read_unlock_bh(&p->conn_lock);

	return ret;
}

static void v4v_cancel_pending(struct sock *sk,
			       struct v4v_addr *src,
			       uint32_t conn_id)
{
	struct sk_buff *skb;
	struct v4v_streamhdr *sh;
	struct v4v_addr *addr;

	spin_lock_bh(&sk->sk_receive_queue.lock);
	skb_queue_walk(&sk->sk_receive_queue, skb) {
		addr = (void *)skb->data;
		sh = (void *)(addr + 1);

		if (!pskb_may_pull(skb, sizeof (*sh) + sizeof (*addr)))
			continue;

		if (sh->conid == conn_id &&
		    !memcmp(addr, src, sizeof (*addr))) {

			WARN_ON(!(sh->flags & V4V_SHF_SYN));
			__skb_unlink(skb, &sk->sk_receive_queue);
			kfree_skb(skb);
			break;
		}
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);
}

static int v4v_do_sock_rx_once(struct sock *sk)
{
	struct v4v_sock *v = v4v_sk(sk);
	struct sock *conn = NULL;
	struct v4v_ring_msghdr *mh;
	struct v4v_addr src;
	struct sk_buff *skb;
	struct v4v_streamhdr *sh;
	int cont = 1;

	mh = v4v_ring_peek(v->ring, sizeof (*mh));

	if (!mh)
		return 0;

	src = mh->source;

	if (mh->protocol == V4V_PROTO_STREAM &&
	    sk->sk_state == V4V_LISTENING) {
		conn = v4v_conn_lookup(sk, &src);
	}

	if (!conn)
		conn = sk;

	skb = v4v_skb_from_ring(v->ring);
	if (!skb)
		return 0;

	sh = (void *)skb->data;
	bh_lock_sock(conn);

	if (conn->sk_type == V4V_LISTENING &&
	    pskb_may_pull(skb, sizeof (*sh)) &&
	    sh->flags & V4V_SHF_RST) {
		/*
		 * This is an RST frame which doesn't match
		 * any of the accepted children socket. Which
		 * indicates that the corresponding SYN frame
		 * may still be sitting in the listening socket
		 * receive queue or backlog.
		 */

		v4v_cancel_pending(conn, &src, sh->conid);
		kfree_skb(skb);
		goto done;
	} else if ((conn->sk_type == SOCK_STREAM) &&
		   (conn->sk_state == V4V_CONNECTING) &&
		   pskb_may_pull(skb, sizeof (*sh)) &&
		   sh->flags & V4V_SHF_ACK) {
		/*
		 * Stream socket doing connect() returned EINPROGRESS.
		 * Finish syn/ack exchange and switch to connected.
		 */

		/* Check connection ID and pull stream header. */
		struct v4v_sock *c = v4v_sk(conn);

		if (sh->conid != c->conn_id)
			goto drop;

		conn->sk_state = V4V_CONNECTED;
		skb_pull(skb, sizeof (*sh));
		goto done;
	} else if (conn->sk_type == SOCK_DGRAM ||
		   conn->sk_state == V4V_LISTENING ||
		   conn->sk_state == V4V_CONNECTING) {
		/*
		 * Push addr in front of data
		 */
		memcpy(skb_push(skb, sizeof (src)), &src, sizeof (src));
	} else if (conn->sk_state == V4V_ACCEPTED ||
		   conn->sk_state == V4V_CONNECTED) {
		struct v4v_sock *c = v4v_sk(conn);

		/*
		 * Check connection ID and pull stream
		 * header
		 */
		if (!pskb_may_pull(skb, sizeof (*sh)))
			goto drop;

		if (sh->conid != c->conn_id)
			goto drop;
		if (sh->flags == V4V_SHF_RST) {
			conn->sk_state = V4V_DISCONNECTED;
			kfree_skb(skb);
			goto done;
		}

		skb_pull(skb, sizeof (*sh));
	} else if (conn->sk_state == V4V_DISCONNECTED)
		goto drop;

	if (sock_owned_by_user(conn) || sk_backlog_rcv(conn, skb)) {
		if (v4v_sk_add_backlog(conn, skb))
			kfree_skb(skb);
	}

	goto done;
drop:
	atomic_inc(&conn->sk_drops);
	kfree_skb(skb);
done:
	if (atomic_read(&conn->sk_rmem_alloc) >= conn->sk_rcvbuf) {
		set_bit(0, &v->rx_blocked);
		cont = 0;
	}

	bh_unlock_sock(conn);

	if (conn != sk)
		__sock_put(conn);

	return cont;
}

static int v4v_do_sock_rx(struct sock *sk)
{
	struct v4v_sock *v = v4v_sk(sk);
	int notify = 0;

	if (test_bit(0, &v->rx_blocked))
		return 0;

	while (v4v_do_sock_rx_once(sk))
		notify++;

	return notify;
}

static int v4v_do_rx(void)
{
	struct sock *sk;
	int notify = 0;

	read_lock_bh(&sk_lock);

	sk_for_each(sk, &sk_list) {
		sock_hold(sk);
		notify += v4v_do_sock_rx(sk);
		__sock_put(sk);
	}

	read_unlock_bh(&sk_lock);

	if (notify)
		/* XXX: No reason to fail, but if it does... then what?
		 *	GCC will leave a warning there until the HC interface
		 *	is fixed. */
		HYPERVISOR_v4v_op(V4VOP_notify, NULL, NULL, NULL, 0, 0);

	return notify;
}

/* BH sock lock must be held */
static void v4v_xmit_queue(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = skb_peek(&sk->sk_write_queue))) {
		int rc = v4v_xmit_skb(sk, skb);

		/* Leave it on queue and bail out */
		if (rc == -EAGAIN)
			break;

		if (rc < 0) {
			/*
			 * Do something clever here,
			 * for example report -ENOTCONN to userspace.
			 */
		}

		__skb_unlink(skb, &sk->sk_write_queue);
		kfree_skb(skb); // Should call sock_wfree()
	}
}

static void v4v_do_tx(void)
{
	struct sock *sk;

	read_lock_bh(&sk_lock);

	sk_for_each(sk, &sk_list) {
		struct v4v_sock *v = v4v_sk(sk);

		sock_hold(sk);
		bh_lock_sock(sk);

		if (sk->sk_state == V4V_LISTENING) {
			struct sock *conn;

			read_lock_bh(&v->conn_lock);
			sk_for_each(conn, &v->connections) {
				    sock_hold(conn);
				    bh_lock_sock(conn);

				    v4v_xmit_queue(conn);

				    bh_unlock_sock(conn);
				    __sock_put(conn);
			}
			read_unlock_bh(&v->conn_lock);
		}

		v4v_xmit_queue(sk);

		bh_unlock_sock(sk);
		__sock_put(sk);
	}

	read_unlock_bh(&sk_lock);
}

static void v4v_tasklet_fn(unsigned long data)
{
	v4v_do_tx();
	v4v_do_rx();
}

DECLARE_TASKLET(v4v_tasklet, v4v_tasklet_fn, 0);


/*
 * Interrupt
 */
static irqreturn_t v4v_interrupt(int irq, void *dev_id)
{
	/* Process TX/RX in tasklet */
	tasklet_schedule(&v4v_tasklet);

	return IRQ_HANDLED;
}

/*
 * socket queue recv/send functions.
 */
static void v4v_restart_rx(struct sock *sk)
{
	struct v4v_sock *v = v4v_sk(sk);

	if (v->parent)
		v = v4v_sk(v->parent);

	if (test_and_clear_bit(0, &v->rx_blocked)) {
		tasklet_schedule(&v4v_tasklet);
	}
}

/* This function sleeps, hence no locks can be held. */
static struct sk_buff *v4v_sock_wait(struct sock *sk, int noblock, int *err)
{
	struct sk_buff *skb = NULL;
	long timeo = sock_rcvtimeo(sk, noblock);
	int rc = 0;
	DEFINE_WAIT(wait);

	prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
	skb = skb_dequeue(&sk->sk_receive_queue);
	if (skb)
		goto finish;

	while (!skb) {
		/*
		 * SO_RCVTIMEO:
		 * - If data is received before timeo, return amount of data
		 *   transfered,
		 * - if no data is received before timeo, return -1 with
		 *   errno = EAGAIN || EWOULDBLOCK || EINPROGRESS,
		 * - If the timeout is set to zero (the default) then the
		 *   operation will never timeout.
		 */
		rc = -EAGAIN;
		if (!timeo)
			break;

		if (signal_pending(current)) {
			rc = sock_intr_errno(timeo);
			break;
		}

		timeo = schedule_timeout(timeo);

		rc = sock_error(sk);
		if (rc)
			break;

		 rc = 0;
		skb = skb_dequeue(&sk->sk_receive_queue);
	}

	if (rc)
		goto finish;

	if (sk->sk_type == SOCK_STREAM &&
	    !(sk->sk_state == V4V_CONNECTED ||
	      sk->sk_state == V4V_LISTENING ||
	      sk->sk_state == V4V_ACCEPTED))
		rc = -ENOTCONN;


finish:
	finish_wait(sk_sleep(sk), &wait);

	if (skb)
		v4v_restart_rx(sk);

	*err = rc;
	return skb;
}

static inline void v4v_skb_free(struct sock *sk, struct sk_buff *skb)
{
	consume_skb(skb);
	sk_mem_reclaim_partial(sk);
}

static inline void v4v_skb_drop(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	atomic_inc(&sk->sk_drops);
	sk_mem_reclaim_partial(sk);
}

/* Caller must hold sock lock */
static int __v4v_stream_sendmsg(struct sock *sk,
				//struct iovec *iovec, size_t iov_len, int len,
				struct iov_iter *msg_iter, int len,
				struct v4v_addr *dst, uint32_t conn_id,
				int stream_flags, int noblock)
{
	int rc;
	struct sk_buff *skb;
	struct v4v_addr *addr;
	struct v4v_streamhdr *sh;

	release_sock(sk);
	skb = sock_alloc_send_skb(sk, len + sizeof (*sh) + sizeof (*addr),
				  noblock, &rc);
	lock_sock(sk);
	if (!skb)
		return rc;
	skb_reserve(skb, sizeof (*addr));

	sh = (void *)skb_put(skb, sizeof (*sh));
	sh->conid = conn_id;
	sh->flags = stream_flags;

	if (msg_iter && len) {
		rc = copy_from_iter(skb_put(skb, len), len, msg_iter);
		//rc = memcpy_fromiovec(skb_put(skb, len), iovec, len);
		if (rc != len) {
			kfree_skb(skb);
			return rc;
		}
	}

	/* Push destination before payload */
	addr = (void *)skb_push(skb, sizeof (*dst));
	*addr = *dst;

	spin_lock_bh(&sk->sk_write_queue.lock);

	if (!skb_queue_empty(&sk->sk_write_queue) ||
	    (rc = v4v_xmit_skb(sk, skb)) == -EAGAIN) {
		__skb_queue_tail(&sk->sk_write_queue, skb);
		rc = len;
	} else {
		if (rc > 0)
			rc -= sizeof (*sh);
		kfree_skb(skb);
	}

	spin_unlock_bh(&sk->sk_write_queue.lock);

	return rc;
}

/* Caller must hold sock lock */
static int __v4v_dgram_sendmsg(struct sock *sk, /* struct iovec *iovec, size_t iov_len, */
			       struct iov_iter *msg_iter,
			       int len, struct v4v_addr *dst, int noblock)
{
	int rc;
	struct sk_buff *skb;
	struct v4v_addr *addr;

	release_sock(sk);
	skb = sock_alloc_send_skb(sk, len + sizeof (*dst), noblock, &rc);
	lock_sock(sk);
	if (!skb)
		return rc;
	skb_reserve(skb, sizeof (*dst));

	if (msg_iter && len) {
		//rc = memcpy_fromiovec(skb_put(skb, len), iovec, len);
		rc = copy_from_iter(skb_put(skb, len), len, msg_iter);
		if (rc != len) {
			kfree_skb(skb);
			return rc;
		}
	}

	/* Push destination before payload */
	addr = (void *)skb_push(skb, sizeof (*dst));
	*addr = *dst;

	spin_lock_bh(&sk->sk_write_queue.lock);

	if (!skb_queue_empty(&sk->sk_write_queue) ||
	    (rc = v4v_xmit_skb(sk, skb)) == -EAGAIN) {
		__skb_queue_tail(&sk->sk_write_queue, skb);
		rc = len;
	} else
		kfree_skb(skb);

	spin_unlock_bh(&sk->sk_write_queue.lock);

	return rc;
}

/*
 * Socket ops
 */

static int v4v_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);

	if (!sk)
		return 0;

	sock_orphan(sk);

	lock_sock(sk);

	if (sk->sk_type == SOCK_STREAM) {
		switch (sk->sk_state) {
		case V4V_CONNECTED:
		case V4V_CONNECTING:
		case V4V_ACCEPTED:
			/* xmit reset */
			__v4v_stream_sendmsg(sk, NULL, /* 0,*/ 0, &v->peer,
					     v->conn_id, V4V_SHF_RST,
					     0);
			sk->sk_state = V4V_DISCONNECTED;
			break;
		default:
			break;
		}

		if (v->parent) {
			struct v4v_sock *l = v4v_sk(v->parent);

			write_lock_bh(&l->conn_lock);
			sk_del_node_init(sk);
			write_unlock_bh(&l->conn_lock);

			/* Release ref to listening sock */
			sock_put(v->parent);
		}
	}

	if (v->ring) {
		write_lock_bh(&sk_lock);
		sk_del_node_init(sk);
		write_unlock_bh(&sk_lock);

		v4v_unregister_ring(v);
	}

	release_sock(sk);

	sock_put(sk);

	return 0;
}

static int __v4v_bind(struct sock *sk, struct v4v_address *addr)
{
	int rc;
	struct v4v_sock *v = v4v_sk(sk);

	rc = v4v_register_ring(v, addr, 32 * PAGE_SIZE);
	if (rc)
		return rc;

	sk->sk_state = V4V_BOUND;

	write_lock_bh(&sk_lock);
	sk_add_node(sk, &sk_list);
	write_unlock_bh(&sk_lock);

	return rc;
}

static int v4v_bind(struct socket *sock,
		    struct sockaddr *uaddr,
		    int sockaddr_len)
{
	struct sock *sk = sock->sk;
	struct sockaddr_v4v *addr = (struct sockaddr_v4v *)uaddr;
	int rc = 0;

	if (!addr || addr->sa_family != PF_V4V)
		return -EINVAL;

	if (sockaddr_len != sizeof (*addr))
		return -EINVAL;

	lock_sock(sk);
	rc = __v4v_bind(sk, &addr->sa_addr);
	release_sock(sk);

	return rc;
}

static int v4v_connect(struct socket *sock,
		       struct sockaddr *uaddr,
		       int sockaddr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);
	struct sockaddr_v4v *addr = (struct sockaddr_v4v *)uaddr;
	int noblock = flags & O_NONBLOCK;
	struct v4v_addr *src;
	struct v4v_streamhdr *sh;
	struct sk_buff *skb;
	int rc = 0;

	if (!addr || addr->sa_family != PF_V4V)
		return -EINVAL;

	if (sockaddr_len != sizeof (*addr))
		return -EINVAL;

	lock_sock(sk);

	if (sk->sk_state == V4V_IDLE) {
		/* Auto bind */
		struct v4v_address baddr = {
			.port = 0,
			.domain = V4V_DOMID_ANY,
		};

		rc = __v4v_bind(sk, &baddr);
		if (rc)
			goto release;
	}

	switch (sk->sk_type) {
	case SOCK_DGRAM:
		switch (sk->sk_state) {
		case V4V_BOUND:
		case V4V_CONNECTED:
			v->peer.domain = addr->sa_addr.domain;
			v->peer.port = addr->sa_addr.port;
			sk->sk_state = V4V_CONNECTED;
			break;
		default:
			rc = -EINVAL;
			break;
		}
		break;
	case SOCK_STREAM:
		switch (sk->sk_state) {
		case V4V_BOUND:
			/* Generate pseudo-random connection ID */
			v->conn_id = prandom_u32();
			v->peer.domain = addr->sa_addr.domain;
			v->peer.port = addr->sa_addr.port;

			sk->sk_state = V4V_CONNECTING;
			rc = __v4v_stream_sendmsg(sk, NULL, /*0,*/ 0, &v->peer,
						  v->conn_id, V4V_SHF_SYN,
						  noblock);
			if (rc < 0) {
				sk->sk_state = V4V_BOUND;
				goto release;
			}
			/* Proceed to the CONNECTING case and wait for the ACK */
		case V4V_CONNECTING:
			rc = -EINVAL;
			if (addr->sa_addr.domain != v->peer.domain ||
			    addr->sa_addr.port != v->peer.port)
				goto release;

			release_sock(sk);
			skb = v4v_sock_wait(sk, noblock, &rc);
			lock_sock(sk);
			if (!skb) {
				if (rc == -EAGAIN)
					rc = -EINPROGRESS;
				goto release;
			}

			src = (void *)skb->data;
			sh = (void *)(src + 1);

			if (!pskb_may_pull(skb,
					   sizeof (*src) + sizeof (*sh)) ||
			    memcmp(src, &v->peer, sizeof (*src))) {
				rc = -EPROTO;
				sk->sk_state = V4V_BOUND;
				v4v_skb_drop(sk, skb);
				goto release;
			}

			if (sh->flags == V4V_SHF_ACK) {
				sk->sk_state = V4V_CONNECTED;
			} else {
				sk->sk_state = V4V_BOUND;
				rc = -EPROTO;
				if (sh->flags == V4V_SHF_RST)
					rc = -ECONNREFUSED;
				v4v_skb_free(sk, skb);
				goto release;
			}

			/* Proceed to the CONNECTED case and return if successful */
		case V4V_CONNECTED:
			/* Prevent connecting the same socket twice */
			rc = -EINVAL;
			if (addr->sa_addr.domain != v->peer.domain ||
			    addr->sa_addr.port != v->peer.port)
				goto release;

			/* Nailed it */
			rc = 0;
			break;
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}

release:
	sk_mem_reclaim_partial(sk);
	release_sock(sk);
	return rc;
}

static int v4v_create(struct net *, struct socket *, int, int);

static int v4v_accept(struct socket *sock,
		      struct socket *newsock, int flags)
{
	struct sock *sk = sock->sk;
	int rc;
	int noblock = flags & O_NONBLOCK;
	struct v4v_addr *src;
	struct v4v_streamhdr *sh;
	struct sk_buff *skb;
	struct sock *newsk;
	struct v4v_sock *l = v4v_sk(sk);
	struct v4v_sock *v;

	lock_sock(sk);

	rc = -EOPNOTSUPP;
	if (sk->sk_type != SOCK_STREAM)
		goto release;

	rc = -EINVAL;
	if (sk->sk_state != V4V_LISTENING)
		goto release;

	release_sock(sk);
	skb = v4v_sock_wait(sk, noblock, &rc);
	lock_sock(sk);
	if (!skb)
		goto release;

	src = (void *)skb->data;
	sh = (void *)(src + 1);

	if (!pskb_may_pull(skb, sizeof (*src) + sizeof (*sh)) ||
	    !(sh->flags & V4V_SHF_SYN)) {
		v4v_skb_drop(sk, skb);
		rc = -EPROTO;
		goto release;
	}

	rc = v4v_create(sock_net(sk), newsock, SOCK_STREAM, 0);
	if (rc)
		goto requeue;
	newsk = newsock->sk;
	newsk->sk_state = V4V_ACCEPTED;
	v = v4v_sk(newsk);
	v->peer = *src;
	v->conn_id = sh->conid;

	/* Ship ACK */
	rc = __v4v_stream_sendmsg(sk, NULL, /*0,*/ 0, &v->peer, v->conn_id,
				  V4V_SHF_ACK, noblock);
	if (rc < 0)
		goto release_newsk;

	/*
	 * Grab a reference to the listening socket so the ring
	 * won't get destroyed if it gets closed.
	 */
	sock_hold(sk);

	v->parent = sk;

	write_lock_bh(&l->conn_lock);
	sk_add_node(newsk, &l->connections);
	write_unlock_bh(&l->conn_lock);

	v4v_skb_free(sk, skb);
release:
	release_sock(sk);
	return rc;
release_newsk:
	newsk->sk_state = V4V_IDLE;
	v4v_release(newsock);
	newsock->sk = NULL;
requeue:
	skb_queue_head(&sk->sk_receive_queue, skb);
	goto release;
}

static int v4v_getname(struct socket *sock,
		       struct sockaddr *addr,
		       int *sockaddr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);
	struct sockaddr_v4v *sa = (void *)addr;
	int rc;

	lock_sock(sk);

	if (peer) {
		rc = -ENOTCONN;
		if ((sk->sk_state != V4V_CONNECTED) &&
		    (sk->sk_state != V4V_ACCEPTED))
			goto release;

		sa->sa_addr.port = v->peer.port;
		sa->sa_addr.domain = v->peer.domain;
	} else {
		if (v->parent)
			v = v4v_sk(v->parent);

		rc = -EINVAL;
		if (!v->ring)
			goto release;

		sa->sa_addr.port = v->ring->id.addr.port;
		sa->sa_addr.domain = v->ring->id.addr.domain;
	}

	sa->sa_family = AF_V4V;
	*sockaddr_len = sizeof (*sa);
	rc = 0;
release:
	release_sock(sk);
	return rc;
}

unsigned int v4v_poll(struct file *file, struct socket *sock,
		      poll_table *wait)
{
	struct sock *sk = sock->sk;
	unsigned int mask = 0;

	sock_poll_wait(file, sk_sleep(sk), wait);
	mask = 0;

	/* exceptional events? */
	if (sk->sk_err || !skb_queue_empty(&sk->sk_error_queue))
		mask |= POLLERR;

	/* readable? */
	if (!skb_queue_empty(&sk->sk_receive_queue))
		mask |= POLLIN | POLLRDNORM;

	/* Connection-based need to check for termination and startup */
	if (sk->sk_type == SOCK_STREAM) {
		if (sk->sk_state == V4V_DISCONNECTED)
			mask |= POLLHUP;
		/* connection hasn't started yet? */
		if (sk->sk_state == V4V_CONNECTING)
			/* TODO: Need to check that connect() actually completed! */
			mask |= POLLOUT;
			return mask;
	}

	/* writable? */
	if (sock_writeable(sk))
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
	else
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0) ) /* 4.4 introduce sk_set_bit(). */
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
#else
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
#endif

	return mask;
}

static int v4v_ioctl(struct socket *sock, unsigned int cmd,
		     unsigned long arg)
{
	return -EINVAL;
}

static int v4v_listen(struct socket *sock, int len)
{
	struct sock *sk = sock->sk;
	int rc;

	lock_sock(sk);

	rc = -EOPNOTSUPP;
	if (sk->sk_type != SOCK_STREAM)
		goto release;

	if (sk->sk_state == V4V_IDLE) {
		/* Auto bind */
		struct v4v_address baddr = {
			.port = 0,
			.domain = V4V_DOMID_ANY,
		};

		rc = __v4v_bind(sk, &baddr);
		if (rc)
			goto release;
	}

	sk->sk_state = V4V_LISTENING;
	rc = 0;
release:
	release_sock(sk);
	return rc;
}

static int v4v_setsockopt(struct socket *sock, int level,
			  int optname, char __user *optval, unsigned int optlen)
{
	return -EINVAL;
}

static int v4v_getsockopt(struct socket *sock, int level,
			  int optname, char __user *optval, int __user *optlen)
{
	return -EINVAL;
}

static int v4v_stream_sendmsg(struct socket *sock, struct msghdr *m,
			      size_t len)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);
	int rc;

	if (sk->sk_type != SOCK_STREAM)
		return -EINVAL;

	if (m->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	lock_sock(sk);

	rc = -ENOTCONN;
	if (sk->sk_state != V4V_CONNECTED && sk->sk_state != V4V_ACCEPTED)
		goto release;
	rc = -EISCONN;
	if (m->msg_namelen)
		goto release;

	rc = __v4v_stream_sendmsg(sk, /* m->msg_iov, m->msg_iovlen, len,*/
				  &m->msg_iter, len,
				  &v->peer, v->conn_id, 0,
				  m->msg_flags & MSG_DONTWAIT);
	if (rc == -ECONNREFUSED) {
		rc = sock_error(sk) ? : -EPIPE;
		if (rc == -EPIPE && !(m->msg_flags & MSG_NOSIGNAL))
			send_sig(SIGPIPE, current, 0);
	}

release:
	release_sock(sk);
	return rc;
}

static int v4v_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			      size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);
	struct sockaddr_v4v *sa = msg->msg_name;
	int rc;
	int target;
	int copied = 0;
	struct sk_buff *skb;

	if (sk->sk_type != SOCK_STREAM)
		return -EINVAL;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	/* XXX Implement me */
	if (flags & MSG_PEEK)
		return -EOPNOTSUPP;

	lock_sock(sk);
	rc = -ENOTCONN;
	if (sk->sk_state == V4V_LISTENING)
		goto out;

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	do {
		int to_copy;

		release_sock(sk);
		skb = v4v_sock_wait(sk, flags & MSG_DONTWAIT, &rc);
		lock_sock(sk);
		if (!skb)
			break;

		to_copy = min_t(int, len, skb->len);
		rc = skb_copy_datagram_iter(skb, 0, &msg->msg_iter, to_copy);
		if (rc) {
			v4v_skb_drop(sk, skb);
			break;
		}

		if (to_copy >= skb->len)
			v4v_skb_free(sk, skb);
		else {
			skb_pull(skb, to_copy);
			skb_queue_head(&sk->sk_receive_queue, skb);
		}

		len -= to_copy;
		copied += to_copy;

		if (copied >= target)
			break;
	} while (len > 0);

	if (rc == -ENOTCONN || copied > 0)
		rc = copied;
out:
	if (rc >= 0 && msg->msg_name) {
		sa->sa_family = AF_V4V;
		sa->sa_addr.port = v->peer.port;
		sa->sa_addr.domain = v->peer.domain;
	}
	msg->msg_namelen = sizeof (*sa);
	release_sock(sk);
	return rc;
}

static int v4v_dgram_sendmsg(struct socket *sock, struct msghdr *m,
			     size_t len)
{
	struct sock *sk = sock->sk;
	struct v4v_sock *v = v4v_sk(sk);
	struct v4v_addr dst;
	int rc;

	if (sk->sk_type != SOCK_DGRAM)
		return -EINVAL;

	if (m->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	lock_sock(sk);

	if (m->msg_namelen) {
		struct sockaddr_v4v *sa = m->msg_name;

		rc = -EINVAL;
		if (m->msg_namelen != sizeof (*sa) ||
		    sa->sa_family != AF_V4V)
			goto release;

		dst.port = sa->sa_addr.port;
		dst.domain = sa->sa_addr.domain;
	} else {
		rc = -ENOTCONN;
		if (sk->sk_state != V4V_CONNECTED)
			goto release;
		dst = v->peer;
	}

	rc = __v4v_dgram_sendmsg(sk, /* m->msg_iov, m->msg_iovlen, len, */
				 &m->msg_iter, len,
				 &dst, m->msg_flags & MSG_DONTWAIT);

release:
	release_sock(sk);
	return rc;
}

static int v4v_dgram_recvmsg(struct socket *sock, struct msghdr *msg,
			     size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int rc;
	struct sockaddr_v4v *sa = msg->msg_name;
	struct v4v_addr src;
	struct v4v_addr *addr;
	struct sk_buff *skb;
	size_t len;

	if (sk->sk_type != SOCK_DGRAM)
		return -EINVAL;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	skb = v4v_sock_wait(sk, flags & MSG_DONTWAIT, &rc);
	if (!skb)
		return rc;
	lock_sock(sk);

	rc = -EFAULT;
	if (!pskb_may_pull(skb, sizeof (*addr)))
		goto drop;

	addr = (void *)skb->data;
	src = *addr;
	skb_pull(skb, sizeof (*addr));

	len = skb->len;
	if (len > size) {
		len = size;
		msg->msg_flags |= MSG_TRUNC;
	}

	rc = skb_copy_datagram_iter(skb, 0, &msg->msg_iter, len);
	if (rc)
		goto drop;

	if (msg->msg_name) {
		sa->sa_family = AF_V4V;
		sa->sa_addr.port = src.port;
		sa->sa_addr.domain = src.domain;
	}
	msg->msg_namelen = sizeof (*sa);

	rc = len;

	if (flags & MSG_PEEK)
		skb_queue_head(&sk->sk_receive_queue, skb);
	else
		v4v_skb_free(sk, skb);

	release_sock(sk);
	return rc;
drop:
	v4v_skb_drop(sk, skb);
	release_sock(sk);
	return rc;
}

static const struct proto_ops v4v_stream_ops = {
	.family = PF_UNIX,
	.owner = THIS_MODULE,
	.release = v4v_release,
	.bind = v4v_bind,
	.connect = v4v_connect,
	.socketpair = sock_no_socketpair,
	.accept = v4v_accept,
	.getname = v4v_getname,
	.poll = v4v_poll,
	.ioctl = v4v_ioctl,
	.listen = v4v_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = v4v_setsockopt,
	.getsockopt = v4v_getsockopt,
	.sendmsg = v4v_stream_sendmsg,
	.recvmsg = v4v_stream_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static const struct proto_ops v4v_dgram_ops = {
	.family = PF_UNIX,
	.owner = THIS_MODULE,
	.release = v4v_release,
	.bind = v4v_bind,
	.connect = v4v_connect,
	.socketpair = sock_no_socketpair,
	.accept = v4v_accept,
	.getname = v4v_getname,
	.poll = v4v_poll,
	.ioctl = v4v_ioctl,
	.listen = v4v_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = v4v_setsockopt,
	.getsockopt = v4v_getsockopt,
	.sendmsg = v4v_dgram_sendmsg,
	.recvmsg = v4v_dgram_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto v4v_proto = {
	.name     = "V4V",
	.owner    = THIS_MODULE,
	.obj_size = sizeof (struct v4v_sock),
};

static void v4v_sock_destruct(struct sock *sk)
{
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
	sk_mem_reclaim(sk);
}

static int v4v_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct sock *sk;
	struct v4v_sock *v;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	switch (sock->type) {
	case SOCK_STREAM:
		sock->ops = &v4v_stream_ops;
		break;
	case SOCK_DGRAM:
		sock->ops = &v4v_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	sk = sk_alloc(net, PF_V4V, GFP_ATOMIC, &v4v_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sk->sk_destruct = v4v_sock_destruct;
	sk->sk_backlog_rcv = sock_queue_rcv_skb;
	sk->sk_family = PF_V4V;
	sk->sk_protocol = protocol;
	sk->sk_allocation = GFP_DMA;
	sk->sk_state = V4V_IDLE;

	v = v4v_sk(sk);
	memset(&v->peer, 0, sizeof (struct v4v_addr));
	v->ring = NULL;
	v->pfns = NULL;
	v->rx_blocked = 0;
	v->conn_id = 0;
	v->parent = NULL;
	rwlock_init(&v->conn_lock);
	INIT_HLIST_HEAD(&v->connections);

	return 0;
}

static struct net_proto_family v4v_family_ops = {
	.family = PF_V4V,
	.create = v4v_create,
	.owner  = THIS_MODULE,
};

/*
 * Init/Cleanup
 */

static int v4v_irq = -1;

static int __init af_v4v_init(void)
{
	int rc;

	rc = bind_virq_to_irqhandler(VIRQ_V4V, 0, v4v_interrupt, 0,
				     "v4v", NULL);
	if (rc < 0)
		goto fail_virq;
	v4v_irq = rc;

	rc = proto_register(&v4v_proto, 0);
	if (rc)
		goto fail_proto;

	rc = sock_register(&v4v_family_ops);
	if (rc)
		goto fail_register;


	return 0;
fail_register:
	proto_unregister(&v4v_proto);
fail_proto:
	unbind_from_irqhandler(v4v_irq, NULL);
fail_virq:
	return rc;

}

static void __exit af_v4v_cleanup(void)
{
	sock_unregister(PF_V4V);
	proto_unregister(&v4v_proto);
	unbind_from_irqhandler(v4v_irq, NULL);

	tasklet_kill(&v4v_tasklet);
}

module_init(af_v4v_init);
module_exit(af_v4v_cleanup);
MODULE_LICENSE("GPL");
MODULE_ALIAS("net-pf-" __stringify(PF_V4V));
