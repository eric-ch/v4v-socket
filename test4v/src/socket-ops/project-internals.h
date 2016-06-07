/*
 * Copyright (c) 2016 Assured Information Security, Inc.
 *
 * Author:
 * Eric Chanudet <chanudete@ainfosec.com>
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

#ifndef _PROJECT_INTERNALS_H_
# define _PROJECT_INTERNALS_H_

static inline int __v4vsock_stream(void)
{
    int s;

    s = socket(AF_V4V, SOCK_STREAM, 0);
    if (s < 0) {
        exit(errno);
    }
    return s;
}

static inline int __v4vsock_bstream(struct sockaddr_v4v *sa)
{
    int s;

    s = socket(AF_V4V, SOCK_STREAM, 0);
    if (s < 0) {
        exit(errno);
    }
    if (bind(s, (struct sockaddr *)sa, sizeof (*sa))) {
        exit(errno);
    }
    return s;
}

static inline void sockops_cmd_parse_addr(int  argc, char *argv[],
                                          struct sockaddr_v4v *sa)
{
    unsigned long domid, port;

    if (!sa) {
        exit(EFAULT);
    }
    if (argc < 4) {
        exit(EINVAL);
    }

    if (parse_ul(argv[2], &domid) ||
        parse_ul(argv[3], &port)) {
        exit(EINVAL);
    }
    if ((domid > V4V_DOMID_ANY) ||
        (!port || (port > 65535))) {
        exit(EINVAL);
    }

    sa->sa_family = AF_V4V;
    sa->sa_addr.domain = domid;
    sa->sa_addr.port = port;
}

#endif /* !_PROJECT_INTERNALS_H_ */

