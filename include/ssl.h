/*
 * IRC - Internet Relay Chat, include/ssl.h
 * Written by David Herrmann.
 */


#ifndef INCLUDED_ssl_h
#define INCLUDED_ssl_h


/* config.h is always included, but we also need "ircd_osdep.h"
 * to get the IOResult type.
 */
#include "config.h"
#include "ircd_osdep.h"


/* Forward declarations.
 * Including "listener.h" or "msgq.h" breaks other dependencies.
 */
struct Listener;
struct MsgQ;
struct Client;
struct ssl_session_t;
struct ssl_cred_t;
typedef struct ssl_session_t ssl_session_t;
typedef struct ssl_cred_t ssl_cred_t;


/* If an SSL backend is available, we declare HAVE_SSL. */
#if defined(HAVE_OPENSSL) || defined(HAVE_GNUTLS)
    #define HAVE_SSL
#endif


/* Defines whether the fd is a client or server SSL handle. */
#define SSL_CLIENT 0
#define SSL_SERVER 1


/* Diffie-Hellman bits. */
#define SSL_DH_BITS 1024 /* We support ~ bits. */
#define SSL_DH_RBITS 1024 /* We require the other server to use at least ~ bits. */


/* Set certificate and trusted CAs. */
extern void ssl_setcert(const char *cert);
extern void ssl_clearcert();
extern void ssl_addtrust(const char *trust);
extern void ssl_cleartrusts();


extern void ssl_init(void);
extern void ssl_deinit(void);

extern ssl_cred_t *ssl_cred_new(unsigned int mode, char *cert, char **trusts);
extern void ssl_cred_free(ssl_cred_t *cred);

extern ssl_session_t *ssl_session_new(unsigned int mode);
extern void ssl_session_shutdown(ssl_session_t *ssl);
extern void ssl_session_free(ssl_session_t *ssl);

extern void ssl_accept(struct Listener *listener, signed int fd);
extern signed int ssl_connect(struct Client *cptr);
extern void ssl_close(signed int fd, ssl_session_t *ssl, const char *buf, unsigned int len);

extern signed int ssl_send(signed int fd, ssl_session_t *ssl, const char *buf, unsigned int len);
extern IOResult ssl_recv(signed int fd, ssl_session_t *ssl, char *buf, unsigned int len, unsigned int *count_out);
extern IOResult ssl_sendv(signed int fd, ssl_session_t *ssl, struct MsgQ *buf, unsigned int *count_in, unsigned int *count_out);

extern const char *ssl_cipherstr(ssl_session_t *ssl);


#endif /* INCLUDED_ssl_h */

