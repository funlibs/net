#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>

#define CLASS(p) ((*(unsigned char*)(p))>>6)
#define TCP 1
#define UDP 0

#define HOST_TYPE 0
#define PORT_TYPE 1
#define LOCATION_TYPE 2
#define FORM_TYPE 3

void
closesocket(int socket) {
    shutdown(socket, SHUT_RDWR);
    close(socket);
}

char*
parseurl(char* uri, int type) {
    char* val = NULL;
    if (type == PORT_TYPE) {

    } else if (type == HOST_TYPE) {

    } else if (type == LOCATION_TYPE) {

    } else if (type == FORM_TYPE) {

    }

    return val;
}

static int
parseip(char *name, uint32_t *ip) {
    unsigned char addr[4];
    char *p;
    int i, x;

    p = name;
    for (i = 0; i < 4 && *p; i++) {
        x = strtoul(p, &p, 0);
        if (x < 0 || x >= 256)
            return -1;
        if (*p != '.' && *p != 0)
            return -1;
        if (*p == '.')
            p++;
        addr[i] = x;
    }

    switch (CLASS(addr)) {
        case 0:
        case 1:
            if (i == 3) {
                addr[3] = addr[2];
                addr[2] = addr[1];
                addr[1] = 0;
            } else if (i == 2) {
                addr[3] = addr[1];
                addr[2] = 0;
                addr[1] = 0;
            } else if (i != 4)
                return -1;
            break;
        case 2:
            if (i == 3) {
                addr[3] = addr[2];
                addr[2] = 0;
            } else if (i != 4)
                return -1;
            break;
    }
    *ip = *(uint32_t*) addr;
    return 0;
}

int
netlookup(char *name, uint32_t *ip) {
    struct hostent *he;

    if (parseip(name, ip) >= 0)
        return 0;

    if ((he = gethostbyname(name)) != 0) {
        *ip = *(uint32_t*) he->h_addr;
        return 0;
    }

    return -1;
}

int
netdial(int istcp, char *server, int port) {
    int proto, fd, n;
    uint32_t ip;
    struct sockaddr_in sa;
    socklen_t sn;

    if (netlookup(server, &ip) < 0)
        return -1;

    proto = istcp ? SOCK_STREAM : SOCK_DGRAM;
    if ((fd = socket(AF_INET, proto, 0)) < 0) {
        return -1;
    }

    /* for udp */
    if (!istcp) {
        n = 1;
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof n);
    }

    /* start connecting */
    memset(&sa, 0, sizeof sa);
    memmove(&sa.sin_addr, &ip, 4);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr*) &sa, sizeof sa) < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    sn = sizeof sa;
    if (getpeername(fd, (struct sockaddr*) &sa, &sn) >= 0) {
        return fd;
    }

    /* report error */
    sn = sizeof n;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*) &n, &sn);
    if (n == 0)
        n = ECONNREFUSED;
    close(fd);
    errno = n;
    return -1;
}