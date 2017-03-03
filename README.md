Net
===

Simple wrapper (one header file net.h) around TCP and SSL for unix/linux.

Example:

```c

#define MAX_REPLY 1000

int
main(int argc, char** argv) {

    netdial socket;
    char* request = "GET / HTTP/1.0\n\rHost www.google.fr\n\r\n\r";
    char reply[MAX_REPLY + 1];

    netdial(NET_SSL, "www.google.fr", 443);
    if (socket.fd < 0)
        return(1);
    
    netwrite(socket, request, strlen(request));
   
    while ((count = netread(socket, reply, MAX_REPLY)) > 0) {
        printf("%s", payload);

    netclose(socket);

    return 0;
   
}

```

See *net_http_client.c* for a complete exemple.
