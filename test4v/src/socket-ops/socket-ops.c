#include "project.h"

struct sockops_cmds {
    int (*ops)(int argc, char *argv[]);
    char *cmd;
    char *desc;
};

static int sockops_usage(int argc, char *argv[]);

struct sockops_cmds cmds[] = {
    { sockops_usage,    "help",     "Display help." },
    { sockops_socket,   "socket",   "<stream|dgram>	Create a V4V socket of given type." },
    { sockops_bind,     "bind",     "<addr> <port>	Create a V4V stream socket and binds the given address." },
    { sockops_listen,   "listen",   "<addr> <port>	Create a V4V stream socket, binds the given address and set it listening." },
};

static int sockops_usage(int argc, char *argv[])
{
    unused(argc);
    unused(argv);
    unsigned int i;

    INF("Usage: sockops <command> [...]");
    INF("Commands:");
    for (i = 0; i < ARRAY_LEN(cmds); ++i) {
        INF("%s	%s", cmds[i].cmd, cmds[i].desc);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int i;

    if (argc < 2) {
        sockops_usage(argc, argv);
        return EINVAL;
    }

    for (i = 0; i < ARRAY_LEN(cmds); ++i) {
        if (!strcmp(argv[1], cmds[i].cmd)) {
            return cmds[i].ops(argc, argv);
        }
    }

    /* Unknown command. */
    return ENOSYS;
}

