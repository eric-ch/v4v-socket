#include "project.h"

static struct bufferevent *server = NULL;
static struct event *input = NULL;

/*
 * Recv data from bufferevent and output to STDOUT.
 */
static void v4c_cli_recv(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t n, len = evbuffer_get_length(input);
    char *data;
    unused(ctx);

    data = malloc(len);
    if (!data) {
        ERR("malloc failed (%s).", strerror(errno));
        return;
    }
    n = evbuffer_remove(input, data, len);
    if (n != len) {
        ERR("evbuffer_remove() failed (%s).", strerror(errno));
        goto out;
    }
    n = write(STDOUT_FILENO, data, len);
    if (n != len) {
        ERR("write() failed (%s).", strerror(errno));
    }

out:
    free(data);
}

/*
 * Handle socket events.
 */
static void v4c_cli_event(struct bufferevent *bev, short what, void *ctx)
{
    struct event_base *base = bufferevent_get_base(bev);
    unused(ctx);

    /* Make sure nothing went nuts. */
    assert(bev == server);

    if (what & BEV_EVENT_READING) {
        ERR("Error while reading.");
    }
    if (what & BEV_EVENT_WRITING) {
        ERR("Error while writing.");
    }
    if (what & BEV_EVENT_EOF) {
        ERR("EOF reached.");
    }
    if (what & BEV_EVENT_ERROR) {
        ERR("Unrecoverable error encountered.");
    }
    if (what & BEV_EVENT_TIMEOUT) {
        ERR("Specified timout reached.");
    }
    if (what & BEV_EVENT_CONNECTED) {
        ERR("Connect operation done.");
    }
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        event_base_loopexit(base, NULL);
    }
}

/*
 * Read STDIN and send to the bufferevent.
 */
static void v4c_send_stdin(evutil_socket_t fd, short what, void *ctx)
{
    struct bufferevent *bev = ctx;
    char data[1024];
    int rc;
    unused(what);

    if (!bev) {
        ERR("No client connected yet.");
        return;
    }

    rc = read(fd, data, sizeof (data));
    if (rc < 0) {
        ERR("read() failed (%s).", strerror(errno));
        return;
    }
    data[rc] = '\0';
    evbuffer_add(bufferevent_get_output(bev), data, rc);
}

/*
 * Create a new event calling v4c_send_stdin when something is ready on STDIN.
 */
static struct event *v4c_stdin_ev_new(struct event_base *base,
                                      struct bufferevent *output)
{
    struct event *ev;

    ev = event_new(base, STDIN_FILENO, EV_READ | EV_PERSIST,
                   v4c_send_stdin, output);
    if (!ev) {
        ERR("event_new() failed (%s).", strerror(errno));
        return NULL;
    }
    event_add(ev, NULL);

    return ev;
}

/*
 * Client events.
 */
int v4c_cli_run(struct event_base *base, domid_t domid, unsigned long port)
{
    struct sockaddr_v4v sa = {
        .sa_family = AF_V4V,
        .sa_addr = {
            .domain = domid,
            .port = port
        },
    };
    int rc;

    assert(!server);
    assert(!input);

    server = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!server) {
        rc = EVUTIL_SOCKET_ERROR();
        WRN("Failed to open socket (%s).",
            evutil_socket_error_to_string(rc));
        return -rc;
    }

    rc = bufferevent_socket_connect(server, (struct sockaddr*)&sa, sizeof (sa));
    if (rc) {
        rc = EVUTIL_SOCKET_ERROR();
        WRN("Failed to connect socket (%s).",
            evutil_socket_error_to_string(rc));
        bufferevent_free(server);
        return -rc;
    }
    bufferevent_setcb(server, v4c_cli_recv, NULL, v4c_cli_event, NULL);
    bufferevent_enable(server, EV_READ | EV_WRITE);

    input = v4c_stdin_ev_new(base, server);
    if (!input) {
        bufferevent_free(server);
    }

    event_base_dispatch(base);

    event_free(input);
    /* v4c_cli_event will call bufferevent_free(server). */

    return 0;
}

