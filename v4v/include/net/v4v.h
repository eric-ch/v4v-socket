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

#ifndef _V4V_H
#define _V4V_H

#include <linux/v4v.h>
#include <xen/v4v.h>

enum {
        V4V_IDLE = 0,
        V4V_BOUND,
        V4V_LISTENING,
        V4V_ACCEPTED,
        V4V_CONNECTING,
        V4V_CONNECTED,
        V4V_DISCONNECTED,
};

struct v4v_sock {
        struct sock sk;

        struct v4v_addr peer;

        unsigned long rx_blocked; /* Skip ring */
        struct v4v_ring *ring;
        struct v4v_pfn_list *pfns;

        /* Only for stream sockets */
        uint32_t conn_id;
        struct sock *parent;
        rwlock_t conn_lock;
        struct hlist_head connections;
        struct hlist_node conn_node;
};

static inline struct v4v_sock *v4v_sk(struct sock *sk)
{
        return (struct v4v_sock *)sk;
}

static inline size_t v4v_ring_data_avail(volatile struct v4v_ring *ring)
{
        int32_t l = ring->tx_ptr - ring->rx_ptr;

        if (l >= 0)
                return l;

        return ring->len + l;
}

static inline void *
v4v_ring_peek(volatile struct v4v_ring *ring, size_t len)
{
        if ((ring->rx_ptr > ring->tx_ptr) &&
            ((ring->rx_ptr + len) > ring->len))
                return NULL;

        if ((ring->rx_ptr <= ring->tx_ptr) &&
            ((ring->rx_ptr + len) > ring->tx_ptr))
                return NULL;

        return (void *)&ring->ring[ring->rx_ptr];
}

#endif /* _V4V_H */
