/*
 * Copyright (c) 2016 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _XEN_V4V_H
#define _XEN_V4V_H

#include <xen/interface/xen.h>

#ifndef _hypercall6
# include <xen/hypercall6.h>
#endif
/*
 *      V4VOP_register_ring(XEN_GUEST_HANDLE(struct v4v_ring) ring,
 *                          XEN_GUEST_HANDLE(struct v4v_pfn_list) pfns) -
 *
 *      Registers a ring with Xen, if a ring with the same v4v_ring_id exists,
 *      this ring takes its place, registration will not change tx_ptr
 *      unless it is invalid
 */
#define V4VOP_register_ring         1

/*
 *      V4VOP_unregister_ring(int,
 *                            XEN_GUEST_HANDLE(struct v4v_ring) ring) -
 *
 */
#define V4VOP_unregister_ring       2

/*
 *      V4VOP_send(XEN_GUEST_HANDLE(struct v4v_addr) src,
 *                 XEN_GUEST_HANDLE(struct v4v_addr) dst,
 *                 XEN_GUEST_HANDLE(void) buf,
 *                 uint32_t len,
 *                 uint32_t protocol) -
 *
 *      Sends len bytes of buf to dst, giving src as the source address (Xen
 *      will ignore src->domain and put your domain in the actual message).
 *
 *      Xen first looks for a ring with id.addr == dst and
 *      id.partner == sending_domain, if that fails it looks for id.addr == dst
 *      and id.partner == DOMID_ANY.
 *
 *      The protocol parameter is the 32 bit protocol number used for the
 *      message, most likely V4V_PROTO_DGRAM or V4V_PROTO_STREAM.
 *      If insufficient space exists, it will return -EAGAIN and xen will twing
 *      the V4V_INTERRUPT when sufficient space becomes available.
 *
 */
#define V4VOP_send                  3

/*
 *      V4VOP_notify(XEN_GUEST_HANDLE(struct v4v_ring_data) buf) -
 *
 *      Asks xen for information about other rings in the system,
 *      buf contains an array of struct v4v_ring_data.
 *
 *      ent->ring is the struct v4v_addr of the ring you want information on
 *      the same matching rules are used as for V4VOP_send.
 *
 *      if the ent->space_required field is not null, xen will check
 *      that there is space in the destination ring for this many bytes
 *      of payload. If there is, it will set the V4V_RING_DATA_F_SUFFICIENT
 *      and CANCEL any pending interrupt for that ent->ring, if insufficient
 *      space is available it will schedule an interrupt and the flag will
 *      not be set.
 *
 *      These flags are set by xen when notify replies:
 *
 *      V4V_RING_DATA_F_EMPTY       ring is empty
 *      V4V_RING_DATA_F_PENDING     interrupt is pending - don't rely on this
 *      V4V_RING_DATA_F_SUFFICIENT  sufficient space for space_required is there
 *      V4V_RING_DATA_F_EXISTS      ring exists
 */
#define V4VOP_notify                4

/*      V4VOP_sendv(XEN_GUEST_HANDLE(struct v4v_addr) src,
 *                  XEN_GUEST_HANDLE(struct v4v_addr) dst,
 *                  XEN_GUEST_HANDLE(struct v4v_iov) iov,
 *                  uint32_t niov,
 *                  uint32_t protocol) -
 *
 *      Identical to V4VOP_send except rather than buf and len it takes
 *      an array of struct v4v_iov and the length of the array.
 */

#define V4VOP_sendv                 5

#ifndef HYPERVISOR_v4v_op
#define __HYPERVISOR_v4v_op         39
static inline int __must_check
HYPERVISOR_v4v_op(int cmd, void *arg1, void *arg2, void *arg3,
                  uint32_t arg4, uint32_t arg5)
{
      return _hypercall6(int, v4v_op, cmd, arg1, arg2, arg3, arg4, arg5);
}
#endif



#define VIRQ_V4V    11

struct v4v_iov
{
        uint64_t iov_base;
        uint64_t iov_len;
} __attribute__((packed));

struct v4v_addr
{
        uint32_t port;
        domid_t domain;
} __attribute__((packed));

struct v4v_ring_id
{
        struct v4v_addr addr;
        domid_t partner;
} __attribute__((packed));

#define V4V_PFN_LIST_MAGIC      0x91dd6159045b302dULL

struct v4v_pfn_list
{
        uint64_t magic;
        uint32_t npage;
        uint32_t pad;
        uint64_t reserved[3];
        uint64_t pages[0];
} __attribute__((packed));

#define V4V_RING_MAGIC          0xdf6977f231abd910ULL

/**
  *     struct v4v_ring -
  *     @id: Ring identifer, Xen only looks at this during register/unregister
  *          and will fill in id.addr.domain.
  *     @len: Length of ring[], must be 8-byte aligned.
  *     @rx_ptr: Modified by domain.
  *     @tx_ptr: Modified by xen.
  *
 */
struct v4v_ring
{
        uint64_t magic;
        struct v4v_ring_id id;
        uint32_t len;
        volatile uint32_t rx_ptr;
        volatile uint32_t tx_ptr;
        uint64_t reserved[4];
        volatile uint8_t ring[0];
} __attribute__((packed));

#define V4V_RING_DATA_MAGIC	0x4ce4d30fbc82e92aULL

#define V4V_RING_DATA_F_EMPTY       1U << 0 /* Ring is empty */
#define V4V_RING_DATA_F_EXISTS      1U << 1 /* Ring exists */
#define V4V_RING_DATA_F_PENDING     1U << 2 /* Pending interrupt exists - */
                                            /* do not rely on this field, */
                                            /* profiling only */
#define V4V_RING_DATA_F_SUFFICIENT  1U << 3 /* Sufficient space to queue */
                                            /* space_required bytes exists */

struct v4v_ring_data_ent
{
        struct v4v_addr ring;
        uint16_t flags;
        uint32_t space_required;
        uint32_t max_message_size;
} __attribute__((packed));

struct v4v_ring_data
{
        uint64_t magic;
        uint32_t nent;
        uint32_t pad;
        uint64_t reserved[4];
        struct v4v_ring_data_ent data[0];
} __attribute__((packed));

/* Messages on the ring are padded to 128 bits */
#define V4V_ROUNDUP(a) (((a) + 0xf) & ~0xf)

#define V4V_SHF_SYN		(1 << 0)
#define V4V_SHF_ACK		(1 << 1)
#define V4V_SHF_RST		(1 << 2)

struct v4v_streamhdr
{
        uint32_t flags;
        uint32_t conid;
} __attribute__((packed));

#define V4V_PROTO_DGRAM     0x3c2c1db8
#define V4V_PROTO_STREAM    0x70f6a8e5

struct v4v_ring_msghdr
{
        uint32_t len;
        struct v4v_addr source;
        uint16_t pad;
        uint32_t protocol;
        uint8_t data[0];
} __attribute__((packed));

#endif /* _XEN_V4V_H */
