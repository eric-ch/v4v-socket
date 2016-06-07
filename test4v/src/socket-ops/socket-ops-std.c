#include "project.h"

int sockops_socket(int argc, char *argv[])
{
    int s, type;

    if (argc != 3) {
        return EINVAL;
    }
    if (!strcmp(argv[2], "stream")) {
        type = SOCK_STREAM;
    } else if (!strcmp(argv[2], "dgram")) {
        type = SOCK_DGRAM;
    } else {
        return EINVAL;
    }

    s = socket(AF_V4V, type, 0);
    if (s < 0) {
        return -errno;
    }
    return 0;
}

int sockops_bind(int argc, char *argv[])
{
    int s;
    struct sockaddr_v4v sa, osa;
    socklen_t osa_len = sizeof (sa);

    sockops_cmd_parse_addr(argc, argv, &sa);
    s = __v4vsock_stream();

    if (bind(s, (struct sockaddr *)&sa, sizeof (sa))) {
        return errno;
    }

    if (getsockname(s, (struct sockaddr *)&osa, &osa_len)) {
        return errno;
    }
    if (osa_len != sizeof (sa) ||
        osa.sa_family != sa.sa_family ||
        //osa.sa_addr.domain != sa.sa_addr.domain ||
        // Actually we cannot bind any addr and without establishing connection, the ring->id.addr
        // structure will be used in .getname() callback.
        // The .domain field gets filled in Xen V4V code with d->domain_id, so we could only expect
        // our own domid to be returned here.
        // XXX: That is an interesting side effect.
        osa.sa_addr.port != sa.sa_addr.port) {
        INF("%u %u vs %u %u",
            osa.sa_addr.domain, osa.sa_addr.port, sa.sa_addr.domain, sa.sa_addr.port);
        return EINVAL;
    }
    return 0;
}

int sockops_listen(int argc, char *argv[])
{
    int s;
    struct sockaddr_v4v sa;

    sockops_cmd_parse_addr(argc, argv, &sa);
    s = __v4vsock_bstream(&sa);

    if (listen(s, 1)) {
        return errno;
    }
    return 0;
}

