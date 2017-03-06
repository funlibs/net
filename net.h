/*
 * Copyright (c) 2017 Sebastien Serre <ssbx@sysmo.io>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NET_H
#define NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>


#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define CLASS(p) ((*(unsigned char*)(p))>>6)

#define NET_TCP 0
#define NET_UDP 1
#define NET_SYNC 0
#define NET_ASYNC 2
#define NET_NOSSL 0
#define NET_SSL 4
#define __USE_ASYNC(opts) (opts & NET_ASYNC)
#define __USE_UDP(opts)   (opts & NET_UDP)
#define __USE_SSL(opts)   (opts & NET_SSL)


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

    typedef struct {
        X509 *cert;
        SSL_CTX *ctx;
        SSL *ssl;
        int fd;
        int status;
    } NetSocket;

    char ssl_error_none[] = "none";
    char ssl_error_zero_return[] = "The TLS/SSL connection has been closed";
    char ssl_error_want_write[] = "The Write operation did not complete";
    char ssl_error_want_read[] = "The Read operation did not complete";

    char ssl_error_want_connect[] = "The Connect opertation did not complete";
    char ssl_error_want_accept[] = "The Accept opertation did not complete";
    char ssl_error_want_x509_lookup[] = "The x509 lookup did not complete";
    char ssl_error_ssl[] =
            "A failure in the SSL library occurred (protocol error?)";

    char*
    netGetStatus(NetSocket net_socket) {
        if (net_socket.status < 9) {
            switch (net_socket.status) {
                case SSL_ERROR_NONE:
                    return ssl_error_none;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    return ssl_error_zero_return;
                    break;
                case SSL_ERROR_WANT_READ:
                    return ssl_error_want_read;
                    break;
                case SSL_ERROR_WANT_WRITE:
                    return ssl_error_want_write;
                    break;
                case SSL_ERROR_WANT_ACCEPT:
                    return ssl_error_want_accept;
                    break;
                case SSL_ERROR_WANT_CONNECT:
                    return ssl_error_want_connect;
                    break;
                case SSL_ERROR_WANT_X509_LOOKUP:
                    return ssl_error_want_x509_lookup;
                    break;
                case SSL_ERROR_SSL:
                    return ssl_error_ssl;
                    break;
            }
        }

        return strerror(net_socket.status);
    }

    /*
     * Cleanup netsocket structure.
     */
    NetSocket
    netClose(NetSocket socket) {
        NetSocket empty = {NULL, NULL, NULL, -1, errno};
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
     * TODO serious url parser
     */
    void
    __parseUrl(char url_str[]) {
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

    int
    __parseIP(char *name, uint32_t *ip) {
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
    __hostLookup(char *name, uint32_t *ip) {
        struct hostent *he;

        if (__parseIP(name, ip) >= 0)
            return 0;

        if ((he = gethostbyname(name)) != 0) {
            *ip = *(uint32_t*) he->h_addr_list[0];
            return 0;
        }

        return -1;
    }

    /*
     * Write to a socket, either SSL or pure TCP.
     */
    int
    netWrite(NetSocket socket, char* payload, int size) {
        int c;
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
    netRead(NetSocket socket, char* payload, int size) {

        if (socket.ssl != NULL) {
            return SSL_read(socket.ssl, payload, size);
        } else {
            return read(socket.fd, payload, size);
        }

    }

    /*
     * Opts can be:
     * - NET_TCP/NET_UDP
     * - NET_SYNC/NET_ASYNC
     * - NET_NOSSL/NET_SSL
     *
     * Default (0) is the same as NET_TCP | NET_SYNC | NET_NOSSL
     */
    NetSocket
    __netDialSSL(char *server, int port, int opts) {
        int proto, n;
        uint32_t ip;
        struct sockaddr_in sa;
        socklen_t sn;
        NetSocket net_socket = {NULL, NULL, NULL, -1, 0};

        if (__hostLookup(server, &ip) < 0) {
            return netClose(net_socket);
        }

        if (__USE_UDP(opts)) {
            proto = SOCK_DGRAM;
        } else {
            proto = SOCK_STREAM;
        }

        if ((net_socket.fd = socket(AF_INET, proto, 0)) < 0) {
            return netClose(net_socket);
        }

        /* for udp */
        if (__USE_UDP(opts)) {
            n = 1;
            setsockopt(net_socket.fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof n);
        }

        /* maybe async */
        if (__USE_ASYNC(opts))
            if ((fcntl(net_socket.fd, F_SETFL,
                    fcntl(net_socket.fd, F_GETFL) | O_NONBLOCK)) < 0)
                return netClose(net_socket);


        /* start connecting */
        memset(&sa, 0, sizeof sa);
        memmove(&sa.sin_addr, &ip, 4);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        if (connect(net_socket.fd, (struct sockaddr*) &sa, sizeof sa) < 0
                && errno != EINPROGRESS)
            return netClose(net_socket);

        sn = sizeof sa;
        if (getpeername(net_socket.fd, (struct sockaddr*) &sa, &sn) >= 0)
            return net_socket;

        /* report error */
        sn = sizeof n;
        getsockopt(net_socket.fd, SOL_SOCKET, SO_ERROR, (void*) &n, &sn);
        if (n == 0)
            n = ECONNREFUSED;
        errno = n;
        return netClose(net_socket);
    }

    NetSocket
    __netDialTCP(char *server, int port, int opts) {

        int err, err2;
        BIO *certbio = NULL;
        const SSL_METHOD *method;
        NetSocket socket = {NULL, NULL, NULL, -1}, tcpsocket;

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
            return netClose(socket);
        }

        /* ---------------------------------------------------------- *
         * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
         * ---------------------------------------------------------- */
        method = SSLv23_client_method();

        /* ---------------------------------------------------------- *
         * Try to create a new SSL context                            *
         * ---------------------------------------------------------- */
        if ((socket.ctx = SSL_CTX_new(method)) == NULL) {
            return netClose(socket);
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
        tcpsocket = __netDialSSL(server, port, opts);
        socket.fd = tcpsocket.fd;

        if (socket.fd < 0)
            return netClose(socket);

        /* ---------------------------------------------------------- *
         * Attach the SSL session to the socket descriptor            *
         * ---------------------------------------------------------- */
        SSL_set_fd(socket.ssl, socket.fd);

        /* ---------------------------------------------------------- *
         * Try to SSL-connect here, returns 1 for success             *
         * ---------------------------------------------------------- */
        if ((err = SSL_connect(socket.ssl)) != 1) {
            if ((err2 = SSL_get_error(socket.ssl, err)) != SSL_ERROR_SYSCALL)
                errno = err2;

            return netClose(socket);
        }

        /* ---------------------------------------------------------- *
         * Get the remote certificate into the X509 structure         *
         * ---------------------------------------------------------- */
        if ((socket.cert = SSL_get_peer_certificate(socket.ssl)) == NULL)
            return netClose(socket);

        return socket;
    }

    NetSocket
    netAccept(NetSocket net_socket) {
        int cfd, one, fd, port;
        struct sockaddr_in sa;
        unsigned char *ip;
        char remote[100];
        socklen_t len;
        fd = net_socket.fd;
        NetSocket rsocket = {NULL, NULL, NULL, -1, 0};

        len = sizeof sa;
        if ((cfd = accept(fd, (void*) &sa, &len)) < 0) {
            return netClose(rsocket);
        }

        ip = (unsigned char *) & sa.sin_addr;
        port = ntohs(sa.sin_port);
        // printf("connexion from %s port %i", ip, port);

        one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char*) &one, sizeof one);
        rsocket.fd = cfd;
        return rsocket;
    }

    /*
     * Opts can be:
     * - NET_TCP/NET_UDP
     * - NET_SYNC/NET_ASYNC
     * - NET_NOSSL/NET_SSL
     *
     * Default (0) is the same as NET_TCP | NET_SYNC | NET_NOSSL
     */
    NetSocket
    netAnnounce(char *server, int port, int opts) {
        int n, proto;
        struct sockaddr_in sa;
        socklen_t sn;
        uint32_t ip;
        NetSocket netsocket = {NULL, NULL, NULL, -1};

        if (__USE_UDP(opts)) {
            proto = SOCK_DGRAM;
        } else {
            proto = SOCK_STREAM;
        }
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        if (server != ((void*) 0) && strcmp(server, "*") != 0) {
            if (__hostLookup(server, &ip) < 0)
                return netsocket;
            memmove(&sa.sin_addr, &ip, 4);
        }
        sa.sin_port = htons(port);
        if ((netsocket.fd = socket(AF_INET, proto, 0)) < 0) {
            return netClose(netsocket);
        }

        /* set reuse flag for tcp */
        if ((!__USE_UDP(opts)) && getsockopt(netsocket.fd, SOL_SOCKET, SO_TYPE,
                (void*) &n, &sn) >= 0) {
            n = 1;
            setsockopt(netsocket.fd, SOL_SOCKET,
                    SO_REUSEADDR, (char*) &n, sizeof n);
        }

        if (bind(netsocket.fd, (struct sockaddr*) &sa, sizeof sa) < 0) {
            return netClose(netsocket);
        }

        if (proto == SOCK_STREAM)
            listen(netsocket.fd, 16);

        if (__USE_ASYNC(opts))
            if ((fcntl(netsocket.fd, F_SETFL,
                    fcntl(netsocket.fd, F_GETFL) | O_NONBLOCK)) < 0)
                return netClose(netsocket);

        return netsocket;
    }

    /*
     * Opts can be:
     * - NET_TCP/NET_UDP
     * - NET_SYNC/NET_ASYNC
     * - NET_NOSSL/NET_SSL
     *
     * Default (0) is the same as NET_TCP | NET_SYNC | NET_NOSSL
     *
     * IF NET_ASYNC:
     * Next calls to connect, netRead and readWrite will return immediately if
     * fd is not ready for various reason (asynchrnous):
     * - return -1, with errno = EINPROGRESS for connect
     * - return -1, with errno = EAGAIN for netRead/netWrite,
     *
     * It is the role of the user to handle this behaviour.
     *
     * If you do not understand, use netDial.
     * This will presently fail for ssl connections.
     */
    NetSocket
    netDial(char *server, int port, int opts) {
        if (__USE_SSL(opts)) {
            return __netDialTCP(server, port, opts);
        } else {
            return __netDialSSL(server, port, opts);
        }
    }


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // NET_H
