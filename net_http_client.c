/*
 * File:   net_http_client.c
 * Author: Sébastien Serre <sserre at msha.fr>
 *
 * Created on 27 février 2017, 16:58
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net.h>

char HTTP_GET[] =
        "GET / HTTP/1.0\r\n"
        "Host: %s\r\n\r\n";

#define PAYLOAD_MAX 100000
#define REQUEST_MAX 100000

/*
 *
 * Usage:
 * net_example ssl www.example.com
 * net_example nossl www.example.com
 */
int
main(int argc, char** argv) {
    int count, net_type, port;
    char payload[PAYLOAD_MAX + 1], request[REQUEST_MAX + 1];
    netsocket socket;

    if (argc < 3) {
        printf("no enought args");
        return (EXIT_FAILURE);
    }

    port = 80;
    net_type = NET_TCP;
    if (strcmp(argv[1], "ssl") == 0) {
        port = 443;
        net_type = NET_SSL;
    }

    socket = netdial(net_type, argv[2], port);

    if (socket.fd < 0) {
        printf("ERROR: %i\n", socket.status);
        return (EXIT_FAILURE);
    }

    snprintf(request, REQUEST_MAX, HTTP_GET, argv[2]);
    if (netwrite(socket, request, strlen(request)) >= 0) {
        while ((count = netread(socket, payload, PAYLOAD_MAX)) > 0) {
            printf("%s", payload);
        }
    }

    netclose(socket);

    return (EXIT_SUCCESS);
}

