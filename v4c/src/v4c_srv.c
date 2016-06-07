#include "project.h"

static struct evconnlistener *listener = NULL;
static struct bufferevent *client = NULL;
static struct event *input = NULL;

/*
 * Recv data from bufferevent and output to STDOUT.
 */
static void v4c_srv_recv(struct bufferevent *bev, void *ctx)
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
static void v4c_srv_event(struct bufferevent *bev, short what, void *ctx)
{
    struct event_base *base = bufferevent_get_base(bev);
    unused(ctx);

    /* Handle only one client. */
    assert(bev == client);

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
        client = NULL;
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
 * Server events (listener, accept & error).
 * v4c_srv_accept: accept new connection and create associated bufferevent.
 * v4c_srv_accept_error: handle errors on connection.
 */
static void v4c_srv_accept(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *sa, int salen, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    unused(sa);
    unused(salen);
    unused(ctx);

    if (client) {
        WRN("A client is connected already, droping new connection.");
        EVUTIL_CLOSESOCKET(fd);
        return;
    }

    client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!client) {
        WRN("Could not setup connection with the client.");
        return;
    }
    bufferevent_setcb(client, v4c_srv_recv, NULL, v4c_srv_event, client);

    input = v4c_stdin_ev_new(base, client);
    if (!input) {
        WRN("Could not setup read event on STDIN.");
        bufferevent_free(client);
        EVUTIL_CLOSESOCKET(fd);
        return;
    }

    bufferevent_enable(client, EV_READ | EV_WRITE);
}

static void v4c_srv_accept_error(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    unused(ctx);

    ERR("Error on listener: %s. Abort.", evutil_socket_error_to_string(err));
    event_base_loopexit(base, NULL);    /* Stop event loop. */
}

int v4c_srv_run(struct event_base *base, unsigned long port)
{
    struct sockaddr_v4v sa = {
        .sa_family = AF_V4V,
        .sa_addr = {
            .domain = V4V_DOMID_ANY,
            .port = port
        }
    };
    int rc;

    assert(!listener);
    assert(!client);
    assert(!input);
    assert(base);

    listener =
        evconnlistener_new_bind(base, v4c_srv_accept, NULL,
                                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                (struct sockaddr *)&sa, sizeof (sa));
    if (!listener) {
        rc = EVUTIL_SOCKET_ERROR();
        WRN("Failed to initialized listener (%s).",
            evutil_socket_error_to_string(rc));
        return -rc;
    }
    evconnlistener_set_error_cb(listener, v4c_srv_accept_error);

    event_base_dispatch(base);

    event_free(input);
    evconnlistener_free(listener);

    return 0;
}

