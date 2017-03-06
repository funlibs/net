#include <net.h>
#include <stdio.h>

#define MSG_MAX 30

int main(int argc, char** argv) {
    char remote_says[MSG_MAX + 1], message[] = "Hi!";
    NetSocket client;

    client = netDial("localhost", 8889, NET_TCP | NET_SYNC);
    if (client.fd < 0)
        printf("CLIENT: Connection failded: %s\n", netGetStatus(client));

    netWrite(client, message, strlen(message));
    printf("CLIENT: Have sent hello to server\n");
    netRead(client, remote_says, MSG_MAX);
    printf("CLIENT: Server says %s\n", remote_says);
    netClose(client);

    return 0;
}