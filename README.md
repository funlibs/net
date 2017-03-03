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
    netsocket socket;

    socket = netdial(NET_SSL, "www.google.fr", 443);
    if (socket.fd < 0)
        return 1;

    if (netwrite(socket, request, strlen(request)) >= 0)
        while ((count = netread(socket, reply, MAX_PAYLOAD)) > 0)
            printf("%s", reply);

    netclose(socket);

    return 0;
}
```

```sh
gcc exemple.c -L/usr/lib -lssl -lcrypto -o exemple
```

See *net_httpclient.c* for a complete exemple.
