#include <net.h>
#include <stdio.h>

#define MSG_MAX 30

int main(int argc, char** argv) {
    int c;
    char remote_says[MSG_MAX + 1], message[] = "hello from server\n";
    NetSocket listen, rsocket;
    listen = netAnnounce(0, 8889, NET_TCP | NET_SYNC);

    rsocket = netAccept(listen, NET_SYNC);
    if (rsocket.fd < 0) {
        printf("SERVER: Failed to open socket %s\n", netGetStatus(rsocket));
        return 1;
    }

    c = netRead(rsocket, remote_says, MSG_MAX);
    remote_says[c] = '\0';
    printf("SERVER: have received %s from remote client\n", remote_says);
    netWrite(rsocket, message, strlen(message));
    printf("SERVER: have sent hello to client\n");
    netClose(rsocket);

    return 0;
}