#include <net.h>
#include <stdio.h>

#define MSG_MAX 15

int main(int argc, char** argv) {
    char remote_says[MSG_MAX + 1];
    NetSocket listen, rsocket;
    listen = netAnnounce(NET_TCP, 0, 8889, NET_SYNC);

    rsocket = netAccept(listen);
    if (rsocket.fd < 0) {
        printf("SERVER: Failed to open socket %s\n", netGetStatus(rsocket));
        return 1;
    }

    netRead(rsocket, remote_says, MSG_MAX);
    printf("SERVER: have received %s from remote client\n", remote_says);
    netWrite(rsocket, "Hello", MSG_MAX);
    printf("SERVER: have sent hello to client\n");
    netClose(rsocket);

    return 0;
}