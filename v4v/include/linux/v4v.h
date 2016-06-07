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

#ifndef V4V_KERNEL_H
#define V4V_KERNEL_H

#include <linux/types.h>
#include <linux/socket.h>
#include <xen/xen.h>

#define V4V_DOMID_ANY (0x7FFFU)

struct v4v_address {
        uint32_t port;
        domid_t domain;
};

/* For compability with old v4v code */
typedef struct v4v_address v4v_addr_t;

struct sockaddr_v4v {
        __kernel_sa_family_t sa_family;
        struct v4v_address sa_addr;
};

#ifndef AF_V4V
# define AF_V4V AF_SNA /* SNA = IBM main networking. It should not be used with OpenXT */
#endif

#ifndef PF_V4V
# define PF_V4V AF_V4V
#endif

#endif /* V4V_KERNEL_H */
