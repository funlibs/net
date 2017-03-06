#include <net.h>
#include <stdio.h>

#define MSG_MAX 30
#define MAX_EVENTS 10

#define NEED_READ   1
#define NEED_WRITE  2

void
handle_socketEvent(NetSocket *socket) {
    char remote_says[MSG_MAX + 1];
    char message[] = "hello from server\n";
    int r;
    r = netRead(*socket, remote_says, MSG_MAX);

    remote_says[r] = '\0';
    printf("REMOTE_SAYS: %s", remote_says);
    netWrite(*socket, message, strlen(message));
    netClose(*socket);
    free(socket);
}

int main(int argc, char** argv) {
    int n, nfds, epollfd;
    NetSocket listen, rsocket;
    struct epoll_event evt, events[MAX_EVENTS];

    listen = netAnnounce(0, 8889, NET_TCP | NET_ASYNC);
    if (listen.fd <= 0) {
        printf("ERROR: %s\n", netGetStatus(rsocket));
        exit(EXIT_FAILURE);
    }

    if ((epollfd = epoll_create(10)) < 0) {
        printf("ERROR: in epoll create %i\n", errno);
        exit(EXIT_FAILURE);
    }

    evt.data.ptr = &listen;
    evt.events = EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen.fd, &evt) > 0) {
        printf("ERROR: in epoll ctl %i\n", errno);
        netClose(listen);
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("While loop again\n");
        fflush(stdout);
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);

        if (nfds < 0) {
            perror("ERROR: in epoll wait: ");
            netClose(listen);
            exit(EXIT_FAILURE);
        }

        NetSocket *client;
        for (n = 0; n < nfds; ++n) {
            if (events[n].data.ptr == &listen) {
                client = malloc(sizeof (NetSocket));
                *client = netAccept(listen, NET_ASYNC);
                if (client->fd < 0) {
                    perror("Client accept error: ");
                    exit(EXIT_FAILURE);
                }
                printf("fd client is %i\n", client->fd);

                evt.events = EPOLLIN | EPOLLET;
                evt.data.ptr = (void*) client;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client->fd, &evt) < 0) {
                    perror("epol_ctl for client: ");
                    exit(EXIT_FAILURE);
                }
            } else {
                NetSocket *s = (NetSocket *) events[n].data.ptr;
                handle_socketEvent(s);
            }
        }
    }

    return 0;
}