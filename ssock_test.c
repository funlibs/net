/*
 * File:   ssock_test.c
 * Author: Sébastien Serre <sserre at msha.fr>
 *
 * Created on 27 février 2017, 16:58
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ssock.h>

char HTTP_GET[] =
        "GET / HTTP/1.0\r\n"
        "Host: www.example.com\r\n\r\n";

#define PAYLOAD_MAX 100000

/*
 *
 */
int
main(int argc, char** argv) {
    int fd, count;
    char payload[PAYLOAD_MAX + 1];

    if ((fd = netdial(TCP, "www.example.com", 80)) < 0) {
        return (EXIT_FAILURE);
    }


    if (write(fd, HTTP_GET, strlen(HTTP_GET)) >= 0) {
        while ((count = read(fd, payload, PAYLOAD_MAX)) > 0) {
            printf("%s", payload);
        }
    }
    closesocket(fd);

    netdial_ssl();
    return (EXIT_SUCCESS);
}

