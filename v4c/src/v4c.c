#include "project.h"

/*
 * Parameter agregation.
 */
struct v4c_args {
    int listen;
    unsigned long local_port;
    unsigned long port;
    domid_t domid;
};

/*
 * Sanity check on arguments.
 */
static int v4c_sanity(const struct v4c_args *args)
{
    assert(args);
    if (!args->listen && (args->domid == V4V_DOMID_ANY)) {
        WRN("Missing domid.");
        return EINVAL;
    }
    if (args->listen && !args->local_port) {
        WRN("Missing local port.");
        return EINVAL;
    }
    if (!args->listen && !args->port) {
        WRN("Missing port.");
        return EINVAL;
    }
    return 0;
}

static inline int is_valid_port(unsigned long port)
{
    return (port > 0) && (port < 65536);
}

static int v4c_run(const struct v4c_args *args)
{
    int rc;
    struct event_base *base;

    base = event_base_new();
    if (!base) {
        ERR("event_base_new() failed (%s).", strerror(errno));
        return -1;
    }

    if (args->listen) {
        rc = v4c_srv_run(base, args->local_port);
    } else {
        rc = v4c_cli_run(base, args->domid, args->port);
    }

    event_base_free(base);

    return rc;
}

/*
 * Parsing helpers.
 */
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

static inline int parse_domid(const char *nptr, domid_t *domid)
{
    unsigned long d;
    char *end;

    d = strtoul(nptr, &end, 0);
    if (end == nptr) {
        return -EINVAL;
    }
    if (d == ULONG_MAX) {
        return -ERANGE;
    }
    if (d >= V4V_DOMID_ANY) {
        return -EINVAL;
    }
    *domid = (domid_t)d;
    return 0;
}

/*
 * Option handling.
 */
#define OPT_STR "hlp:"
static struct option long_options[] = {
    { "help",   no_argument,        0,  'h' },
    { "listen", no_argument,        0,  'l' },
    { "port",   required_argument,  0,  'p' },
    { 0,        0,                  0,  0 }
};

static int usage(int rc)
{
    INF("Basic usage:");
    INF("v4c domid port");
    INF("v4c -l -p local_port");
    INF("Options:");
    INF("	-l, --listen	listen mode, wait for clients to connect.");
    INF("	-p, --port	set local port number.");

    return rc;
}

int main(int argc, char *argv[])
{
    int rc;
    struct v4c_args args = {
        .listen = 0,
        .local_port = 0,
        .port = 0,
        .domid = V4V_DOMID_ANY,
    };

    if (argc < 1) {
        return usage(EINVAL);
    }

    do {
        int opt, longindex;

        opt = getopt_long(argc, argv, OPT_STR, long_options, &longindex);
        switch (opt) {
            case -1:
                goto getopt_done;
            case 0:
                WRN("Malformed option \"%s\", please fix the code.",
                    long_options[longindex].name);
                return EINVAL;

            case 'h':
                return usage(0);
            case 'l':
                args.listen = 1;
                continue;
            case 'p':
                rc = parse_ul(optarg, &args.local_port);
                if (rc || !is_valid_port(args.local_port)) {
                    WRN("Invalid local port %lu.", args.local_port);
                    return -rc;
                }
                continue;

            default:
                WRN("Unknown option '%c'.", opt);
                return usage(EINVAL);
        }
    } while (1);

getopt_done:
    while (optind < argc) {
        if (args.domid == V4V_DOMID_ANY) {
            parse_domid(argv[optind++], &args.domid);
        } else if (!args.port) {
            rc = parse_ul(argv[optind++], &args.port);
            if (rc || !is_valid_port(args.port)) {
                WRN("Invalid port %s.", argv[optind - 1]);
                return -rc;
            }
        } else {
            WRN("Argument \"%s\" not handled.", argv[optind++]);
        }
    }

    rc = v4c_sanity(&args);
    if (rc) {
        return -rc;
    }

    return v4c_run(&args);
}

