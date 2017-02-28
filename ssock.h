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
#define TCP 1
#define UDP 0

#define HOST_TYPE 0
#define PORT_TYPE 1
#define LOCATION_TYPE 2
#define FORM_TYPE 3

int create_socket(char url_str[], BIO *out);

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

/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;

  /* ---------------------------------------------------------- *
   * Remove the final / from url_str, if there is one           *
   * ---------------------------------------------------------- */
  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

  /* ---------------------------------------------------------- *
   * the first : ends the protocol string, i.e. http            *
   * ---------------------------------------------------------- */
  strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

  /* ---------------------------------------------------------- *
   * the hostname starts after the "://" part                   *
   * ---------------------------------------------------------- */
  strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

  /* ---------------------------------------------------------- *
   * if the hostname contains a colon :, we got a port number   *
   * ---------------------------------------------------------- */
  if(strchr(hostname, ':')) {
    tmp_ptr = strchr(hostname, ':');
    /* the last : starts the port number, if avail, i.e. 8443 */
    strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
    *tmp_ptr = '\0';
  }

  port = atoi(portnum);

  if ( (host = gethostbyname(hostname)) == NULL ) {
    BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }

  /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

  /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */
  memset(&(dest_addr.sin_zero), '\0', 8);

  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
  if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                              sizeof(struct sockaddr)) == -1 ) {
    BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
             hostname, tmp_ptr, port);
  }

  return sockfd;
}

int netdial_ssl() {

  char           dest_url[] = "https://www.hp.com";
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i;

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
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  if ( (ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  server = create_socket(dest_url, outbio);
  if(server != 0)
    BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, server);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  if ( SSL_connect(ssl) != 1 )
    BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
  else
    BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  close(server);
  X509_free(cert);
  SSL_CTX_free(ctx);
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  return(0);
}

