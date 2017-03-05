#include <net.h>
#include <stdio.h>

#define MSG_MAX 15

int main(int argc, char** argv) {
    char remote_says[MSG_MAX + 1];
    NetSocket client;

    client = netDial(NET_TCP, "localhost", 8889);
    if (client.fd < 0)
        printf("CLIENT: Connectio failded %s\n", netGetStatus(client));

    netWrite(client, "Hi!", MSG_MAX);
    printf("CLIENT: Have sent hello to server\n");
    netRead(client, remote_says, MSG_MAX);
    printf("CLIENT: Server says %s\n", remote_says);
    netClose(client);

    return 0;
}