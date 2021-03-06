Net
===

Simple wrapper (one header file) around TCP and SSL for unix/linux.

Example:

HTTP Get request on a webserver 443 port:

```c
#include "net.h"
#include <stdio.h>

#define MAX_REPLY 1000


int
main(int argc, char** argv) {

    int count;
    char* request = "GET / HTTP/1.0\r\nHost: www.google.fr\r\n\r\n";
    char reply[MAX_REPLY + 1];
    NetSocket socket;

    socket = netDial("www.google.fr", 443, NET_TCP | NET_SSL | NET_SYNC);
    if (socket.fd < 0)
        return 1;

    if (netWrite(socket, request, strlen(request)) >= 0)
        while ((count = netRead(socket, reply, MAX_REPLY)) > 0)
            printf("%s", reply);

    netClose(socket);

    return 0;
}
```

```sh
gcc exemple.c -L/usr/lib -lssl -lcrypto -o exemple
```
