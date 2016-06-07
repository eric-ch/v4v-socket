#ifndef _PROJECT_H_
# define _PROJECT_H_

# include "config.h"

# include <sys/time.h>
# include <time.h>

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdarg.h>

# include <limits.h>

# include <errno.h>
# include <assert.h>

# include <string.h>
# include <strings.h>

# include <unistd.h>
# include <fcntl.h>

# include <getopt.h>

# include <linux/v4v.h>

# include <event.h>
# include <event2/listener.h>
# include <event2/bufferevent.h>
# include <event2/buffer.h>

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

int v4c_cli_run(struct event_base *base, domid_t domid, unsigned long port);
int v4c_srv_run(struct event_base *base, unsigned long port);

#endif /* !_PROJECT_H_ */

