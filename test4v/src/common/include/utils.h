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

#ifndef _UTILS_H_
# define _UTILS_H_

# include <stdio.h>
/*
 * Output macro helpers.
 */
#define INF(fmt, ...)   \
    fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define WRN(fmt, ...)   \
    fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...)   \
    fprintf(stderr, "%s:%s:%d:" fmt "\n",   \
            __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)

/*
 * GCC macro helpers.
 */
#define unused(v)   (void)(v)

/*
 * Arithmetics.
 */
#define ARRAY_LEN(a)	(sizeof (a) / sizeof ((a)[0]))

/*
 * Parsing.
 */
# include <stdlib.h>
# include <limits.h>
# include <errno.h>
static inline int parse_ul(const char *nptr, unsigned long *ul)
{
    char *end;

    *ul = strtoul(nptr, &end, 0);
    if (end == nptr) {
        return -EINVAL;
    }
    if (*ul == ULONG_MAX) {
        return -ERANGE;
    }
    return 0;
}

#endif /* !_UTILS_H_ */

