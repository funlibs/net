#include <net.h>
#include <stdio.h>

#define MSG_MAX 30
#define MAX_EVENTS 10

int main(int argc, char** argv) {
    int epollfd, nfds, i, r, n;
    struct epoll_event evt, events[MAX_EVENTS];
    char remote_says[MSG_MAX + 1], message[] = "Hi!\n";
    NetSocket client;

    if ((epollfd = epoll_create(10)) < 0) {
        perror("ERROR in epoll create: ");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < 10; i++) {
        printf("open conn %i\n", i);
        client = netDial("localhost", 8889, NET_TCP | NET_ASYNC);
        if (client.fd < 0) {
            perror("CLIENT Connection failded: ");
            exit(EXIT_FAILURE);
        }

        evt.data.ptr = &client;
        evt.events = EPOLLIN | EPOLLOUT;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client.fd, &evt) != 0) {
            perror("ERROR in epoll ctl: ");
            netClose(client);
            exit(EXIT_FAILURE);
        }

        printf("CLIENT: Have sent hello to server\n");
        netWrite(client, message, strlen(message));
    }

    nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);

    if (nfds < 0) {
        perror("ERROR in epoll wait: ");
        exit(EXIT_FAILURE);
    }

    for (n = 0; n < nfds; n++) {
        NetSocket *s = (NetSocket *) events[n].data.ptr;
        r = netRead(*s, remote_says, MSG_MAX);
        remote_says[r] = '\0';
        printf("REMOTE SAYS: %s", remote_says);
        netClose(*s);
    }

    return 0;
}