#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <resolv.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define CLASS(p) ((*(unsigned char*)(p))>>6)

#define NET_UDP 0
#define NET_TCP 1
#define NET_SSL 2

#define NET_STATUS_OK 0
#define NET_STATUS_OK_STR "ok"
#define NET_STATUS_RESOLV_ERROR 1
#define NET_STATUS_RESOLV_ERROR_STR "Can not resolve the hostname"
#define NET_STATUS_TCP_EINPROGRESS_ERROR 2
#define NET_STATUS_TCP_EINPROGRESS_ERROR_STR "TCP can not complete connexion"
#define NET_STATUS_TCP_ECONNREFUSED_ERROR 3
#define NET_STATUS_TCP_ECONNREFUSED_ERROR_STR "TCP connexion refused"
#define NET_STATUS_TCP_ERROR 4
#define NET_STATUS_TCP_ERROR_STR "TCP error"
#define NET_STATUS_SSL_CONTEXT_ERROR 5
#define NET_STATUS_SSL_CONTEXT_ERROR_STR "SSL context error"
#define NET_STATUS_SSL_SESSION_ERROR 6
#define NET_STATUS_SSL_SESSION_ERROR_STR "SSL session error"
#define NET_STATUS_SSL_CERT_ERROR 7
#define NET_STATUS_SSL_CERT_ERROR_STR "SSL certificate error"
#define NET_STATUS_SSL_INIT_ERROR 8
#define NET_STATUS_SSL_INIT_ERROR_STR "SSL init error"





#define HOST_TYPE 0
#define PORT_TYPE 1
#define LOCATION_TYPE 2
#define FORM_TYPE 3

typedef struct {
    X509 *cert;
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
    int status;
} netsocket;

/*
 * Cleanup netsocket structure.
 */
static netsocket
resumenetsocket(netsocket socket, int status) {
    netsocket empty = {NULL, NULL, NULL, -1, status};
    if (socket.fd > 0) {
        close(socket.fd);
    }
    if (socket.ssl != NULL) {
        SSL_free(socket.ssl);
    }
    if (socket.cert != NULL) {
        X509_free(socket.cert);
    }
    if (socket.ctx != NULL) {
        SSL_CTX_free(socket.ctx);
    }

    return empty;
}

/*
 * Cleanup netsocket structure.
 */
void
closenetsocket(netsocket socket) {
    resumenetsocket(socket, NET_STATUS_OK);
}

/*
 * TODO serious url parser
 */
void
parseurl(char url_str[]) {
    char hostname[256] = "";
    char portnum[6] = "443";
    char proto[6] = "";
    char *tmp_ptr = NULL;
    int port;
    struct hostent *host;
    struct sockaddr_in dest_addr;

    /* ---------------------------------------------------------- *
     * Remove the final / from url_str, if there is one           *
     * ---------------------------------------------------------- */
    if (url_str[strlen(url_str)] == '/')
        url_str[strlen(url_str)] = '\0';

    /* ---------------------------------------------------------- *
     * the first : ends the protocol string, i.e. http            *
     * ---------------------------------------------------------- */
    strncpy(proto, url_str, (strchr(url_str, ':') - url_str));

    /* ---------------------------------------------------------- *
     * the hostname starts after the "://" part                   *
     * ---------------------------------------------------------- */
    strncpy(hostname, strstr(url_str, "://") + 3, sizeof (hostname));

    /* ---------------------------------------------------------- *
     * if the hostname contains a colon :, we got a port number   *
     * ---------------------------------------------------------- */
    if (strchr(hostname, ':')) {
        tmp_ptr = strchr(hostname, ':');
        /* the last : starts the port number, if avail, i.e. 8443 */
        strncpy(portnum, tmp_ptr + 1, sizeof (portnum));
        *tmp_ptr = '\0';
    }

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

/*
 * Write to a socket, either SSL or pure TCP.
 */
int
netwrite(netsocket socket, char* payload, int size) {

    if (socket.ssl != NULL) {
        return SSL_write(socket.ssl, payload, size);
    } else {
        return write(socket.fd, payload, size);
    }

}

/*
 * Read from SSL/TCP socket.
 */
int
netread(netsocket socket, char* payload, int size) {

    if (socket.ssl != NULL) {
        return SSL_read(socket.ssl, payload, size);
    } else {
        return read(socket.fd, payload, size);
    }

}

netsocket
netdialtcp(int istcp, char *server, int port) {
    int proto, fd, n;
    uint32_t ip;
    struct sockaddr_in sa;
    socklen_t sn;
    netsocket net_socket = {NULL, NULL, NULL, -1, NET_STATUS_OK};

    if (netlookup(server, &ip) < 0) {
        return resumenetsocket(net_socket, NET_STATUS_RESOLV_ERROR);
    }

    proto = istcp ? SOCK_STREAM : SOCK_DGRAM;
    if ((fd = socket(AF_INET, proto, 0)) < 0) {
        return resumenetsocket(net_socket, NET_STATUS_TCP_ERROR);
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
        return resumenetsocket(net_socket, NET_STATUS_TCP_EINPROGRESS_ERROR);
    }

    sn = sizeof sa;
    if (getpeername(fd, (struct sockaddr*) &sa, &sn) >= 0) {
        net_socket.fd = fd;
        // ok
        return net_socket;
    }

    /* report error */
    sn = sizeof n;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*) &n, &sn);
    if (n == 0)
        n = ECONNREFUSED;
    close(fd);
    errno = n;
    return resumenetsocket(net_socket, NET_STATUS_TCP_ECONNREFUSED_ERROR);
}

netsocket
netdialssl(char *server, int port) {

    BIO *certbio = NULL;
    const SSL_METHOD *method;
    netsocket socket = {NULL, NULL, NULL, -1}, tcpsocket;

    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    certbio = BIO_new(BIO_s_file());

    /* ---------------------------------------------------------- *
     * initialize SSL library and register algorithms             *
     * ---------------------------------------------------------- */
    if (SSL_library_init() < 0) {
        return resumenetsocket(socket, NET_STATUS_SSL_INIT_ERROR);
    }

    /* ---------------------------------------------------------- *
     * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
     * ---------------------------------------------------------- */
    method = SSLv23_client_method();

    /* ---------------------------------------------------------- *
     * Try to create a new SSL context                            *
     * ---------------------------------------------------------- */
    if ((socket.ctx = SSL_CTX_new(method)) == NULL) {
        return resumenetsocket(socket, NET_STATUS_SSL_CONTEXT_ERROR);
    }

    /* ---------------------------------------------------------- *
     * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
     * ---------------------------------------------------------- */
    SSL_CTX_set_options(socket.ctx, SSL_OP_NO_SSLv2);

    /* ---------------------------------------------------------- *
     * Create new SSL connection state object                     *
     * ---------------------------------------------------------- */
    socket.ssl = SSL_new(socket.ctx);

    /* ---------------------------------------------------------- *
     * Make the underlying TCP socket connection                  *
     * ---------------------------------------------------------- */
    tcpsocket = netdialtcp(NET_TCP, server, port);
    socket.fd = tcpsocket.fd;
    socket.status = tcpsocket.status;

    if (socket.fd < 0) {
        return socket;
    }

    /* ---------------------------------------------------------- *
     * Attach the SSL session to the socket descriptor            *
     * ---------------------------------------------------------- */
    SSL_set_fd(socket.ssl, socket.fd);

    /* ---------------------------------------------------------- *
     * Try to SSL-connect here, returns 1 for success             *
     * ---------------------------------------------------------- */
    if (SSL_connect(socket.ssl) != 1) {
        return resumenetsocket(socket, NET_STATUS_SSL_SESSION_ERROR);
    }

    /* ---------------------------------------------------------- *
     * Get the remote certificate into the X509 structure         *
     * ---------------------------------------------------------- */
    socket.cert = SSL_get_peer_certificate(socket.ssl);
    if (socket.cert == NULL) {
        return resumenetsocket(socket, NET_STATUS_SSL_CERT_ERROR);
    }

    return socket;
}

netsocket
netdial(int socktype, char *server, int port) {
    if (socktype == NET_SSL) {
        return netdialssl(server, port);
    } else {
        return netdialtcp(socktype, server, port);
    }
}