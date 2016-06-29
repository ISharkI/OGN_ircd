/*
 * IRC - Internet Relay Chat, ircd/ssl.c
 * Written by David Herrmann.
 */


/* SSL module.
 * This SSL module is created to be as generic as possible.
 * That is, it is easy to add new backends. We currently support
 * GnuTLS and OpenSSL.
 *
 * The module is built up to encrypt all kinds of network connections.
 * You have to create your socket yourself and accept() or connect() it.
 * The new connected socket has to be passed to this module which then
 * initiates a secure connection. While initiating this connection the
 * socket is kept in a separate queue inside this module. When the
 * connection has been fully established, the client is passed back to
 * the add_connection() function which then passes the client to the
 * authentication module. You can handle the client equally to a normal
 * unencrypted connection, however, the send()/recv() functions have
 * to be changed to the functions provided by this module.
 *
 * The first part of this file defines the backend functions. Only one
 * backend can be enabled at one time. Please add your own backends there.
 *
 * 2009/05/19 --gix
 */


#include "config.h"
#include "ircd.h"
#include "ircd_defs.h"
#include "ircd_events.h"
#include "ircd_snprintf.h"
#include "ircd_osdep.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "msgq.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "client.h"
#include "listener.h"
#include "send.h"
#include "ssl.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>


/* Backend declarations.
 * Please add your backend here. I recommend to leave GnuTLS as the first choice
 * because it is tested most and works perfectly. You can change the backend with
 * the configure script at compile time.
 *
 * Each backend has to declare the following functions:
 * - ssl_be_init(): This is called when the SSL library should be initialized.
 * - ssl_be_deinit(): This is called when the SSL library should be deinitialized.
 * - ssl_be_cred_new(): This should create a new credentials structure.
 * - ssl_be_cred_free(): This should free a previously allocated credentials structure.
 * - ssl_be_session_new(): This should create a new session.
 * - ssl_be_session_connect(): This connects a session with an FD.
 * - ssl_be_session_shutdown(): This should shutdown the Write-Endpoint of a session.
 * - ssl_be_session_free(): This should free a session.
 * - ssl_be_handshake(): This should start/continue the protocol handshake.
 * - ssl_be_send(): This should send data over the connection.
 * - ssl_be_recv(): This should receive data from the connection.
 * - ssl_be_cipherstr(): This should return a string representing the used cipher.
 * - ssl_be_fingerprint(): Validates the peer's socket and returns the fingerprint on success.
 *
 * You should declare the backend specific functions at the end of this files. At this
 * point, every backend has to define the ssl_be_cred_t and ssl_be_session_t structures which
 * represent the credentials and session values used by the backend.
 *
 * Please use the namespace "ssl_be_" in your backend only! All other names may collide
 * with other names.
 * Furthermore look into the dummy to see which checks are already done by the main module
 * and what you do not have to do in your backend.
 */


#if defined(HAVE_GNUTLS)
    /* GnuTLS backend.
     * GnuTLS is licensed under the LGPL and developed by the GNU project.
     * This backend is recommended and tested by the developers of this module.
     */
    #include <gnutls/gnutls.h>
    typedef struct {
        gnutls_certificate_credentials_t cred;
        gnutls_dh_params_t dhparams;
        gnutls_priority_t prio;
    } ssl_be_cred_t;
    typedef gnutls_session_t ssl_be_session_t;
#elif defined(HAVE_OPENSSL)
    /* OpenSSL backend.
     * OpenSSL is developed by independant people and a de-facto standard in the
     * industry. However, the source is *bad* and it has had many bugs in the
     * past. We do not recommend this module!
     */
    /* On some systems, these headers also include the OpenSSL md5 header
     * which itself defines MD5_CTX. This is already defined in ircd_md5.h,
     * hence, we prevent this inclusion here.
     * This fix is really *BAD* but since OpenSSL does not use "namespaces"/
     * "prefixes" there is currently no other solution.
     */
    #define HEADER_MD5_H
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/rand.h>
    typedef SSL_CTX* ssl_be_cred_t;
    typedef SSL* ssl_be_session_t;
    static signed int ssl_be_verify(signed int preverify_ok, X509_STORE_CTX *ctx);
#else
    /* Dummy backend.
     * No backend available. We simply declare fake structures here and handle
     * the connections unencrypted.
     */
    typedef void* ssl_be_cred_t;
    typedef void* ssl_be_session_t;
#endif


/* SSL credentials (cred).
 * An SSL credential is a specific certificate which can be used in many SSL
 * sessions. However, we want to allow to change the certificate at runtime,
 * therefore, we allow several credentials at one time. A new credential is
 * created on /rehash when the certificate changed and then the old creds are
 * marked for removal. New clients are connected with the new credential so we
 * can remove the old creds when there are no more connected clients with this
 * credential.
 * A cred can either be for accepting clients or for connecting yourself as
 * client. We support both, that is, server<->server encryption is also supported.
 * The global creds are stored separated in two single linked lists. If the lists
 * are empty, then no credential has been loaded yet and a new one will be created
 * when a client connects.
 * Thus, only the first credential in this list should be used for new connections,
 * all other credentials are marked for removal.
 */
struct ssl_cred_t;
struct ssl_cred_t {
    struct ssl_cred_t *next;
    unsigned int ref;
    unsigned int mode;
    ssl_be_cred_t be;
};
struct ssl_cred_t *ssl_cli_credlist = NULL;
struct ssl_cred_t *ssl_srv_credlist = NULL;


/* SSL sessions.
 * A session contains all data that is needed by the SSL backend. We also link
 * the session to the used credentials to be able to modify the cred when we
 * modify the session.
 * \fingerprint is NULL when the peer's certificate is not trusted. If it is
 * trusted, then \fingerprint points to a string containing the fingerprint of
 * the peer's certificate.
 */
struct ssl_session_t;
struct ssl_session_t {
    struct ssl_cred_t *cred;
    ssl_be_session_t be;
    char *fingerprint;
};


/* Represents an SSL connection whose handshake is currently pending.
 * If a client connects, it is accepted and then put into the handshake queue.
 * If the handshake timeouts he is rejected, otherwise he is put into the
 * usual user-queue and the auth module continues.
 * This structure is only used in the handshake-queue of accepted SSL clients.
 *
 * ssl_conn_t is the pending outgoing connection. The handshake is performed
 * in this state and then returned to the main module when done. This is handled
 * separately to the client connections.
 */
struct ssl_pending_t {
    ssl_session_t *session;
    struct Socket socket;
    struct Timer timeout;
    signed int fd;
    struct Listener *listener;
};
struct ssl_conn_t {
    ssl_session_t *session;
    struct Timer timeout;
    struct Client *cptr;
    void *olddata;
};


/* Backend functions.
 * See the comment near the top of this file for information on these functions.
 */
unsigned int ssl_be_init();
void ssl_be_deinit();
unsigned int ssl_be_cred_new(unsigned int mode, char *cert, char **trusts, ssl_be_cred_t *cred);
void ssl_be_cred_free(ssl_be_cred_t *cred);
unsigned int ssl_be_session_new(unsigned int mode, ssl_be_cred_t *cred, ssl_be_session_t *session);
unsigned int ssl_be_session_connect(ssl_be_session_t *session, signed int fd);
void ssl_be_session_shutdown(ssl_be_session_t *session);
void ssl_be_session_free(ssl_be_session_t *session);
#define SSL_NEED_WR 0
#define SSL_NEED_RD 1
#define SSL_NEED_RDWR 2
#define SSL_FAILURE 3
#define SSL_SUCCESS 4
unsigned int ssl_be_handshake(unsigned int mode, ssl_be_session_t *session);
const char *ssl_be_cipherstr(ssl_be_session_t *session);
const char *ssl_be_fingerprint(ssl_be_session_t *session);
IOResult ssl_be_send(signed int fd, ssl_be_session_t *ssl, const char *buf, unsigned int *count_out);
IOResult ssl_be_recv(signed int fd, ssl_be_session_t *ssl, char *buf, unsigned int *count_out);


/* Path to the certificate to use. */
char *ssl_cert = NULL;
char **ssl_trusts = NULL;
void ssl_setcert(const char *cert) {
    MyFree(ssl_cert);
    ssl_cert = strdup(cert);
}
void ssl_clearcert() {
    MyFree(ssl_cert);
    ssl_cert = NULL;
}
void ssl_addtrust(const char *trust) {
    unsigned int i;
    char **tmp;
    if(ssl_trusts) {
        i = 0;
        while(ssl_trusts[i]) ++i;
        tmp = MyMalloc(sizeof(char*) * (i + 2));
        i = 0;
        while(ssl_trusts[i]) {
            tmp[i] = ssl_trusts[i];
            ++i;
        }
        tmp[i] = strdup(trust);
        tmp[i + 1] = NULL;
        MyFree(ssl_trusts);
        ssl_trusts = tmp;
    }
    else {
        tmp = MyMalloc(sizeof(char*) * 2);
        tmp[0] = strdup(trust);
        tmp[1] = NULL;
        ssl_trusts = tmp;
    }
}
void ssl_cleartrusts() {
    unsigned int i;
    if(ssl_trusts) {
        i = 0;
        while(ssl_trusts[i]) {
            MyFree(ssl_trusts[i]);
            ++i;
        }
        MyFree(ssl_trusts);
        ssl_trusts = NULL;
    }
}


/* This handles SSL messages.
 * It writes the message to the logfile and prints it on the screen if debugmode is
 * enabled.
 */
#define SSL_NOTICE 0
#define SSL_ERROR 1
#define SSL_DEBUG 2
static void ssl_msg(unsigned int type, const char *msg, ...) {
    va_list list;

    va_start(list, msg);
#ifdef DEBUGMODE
    #define SSL_DEBUGMSG(x, y, z) vdebug((x), (y), (z))
#else
    #define SSL_DEBUGMSG(x, y, z)
#endif
    switch(type) {
        case SSL_NOTICE:
            log_vwrite(LS_SYSTEM, L_NOTICE, 0, msg, list);
            SSL_DEBUGMSG(DEBUG_NOTICE, msg, list);
            break;
        case SSL_ERROR:
            log_vwrite(LS_SYSTEM, L_CRIT, 0, msg, list);
            SSL_DEBUGMSG(DEBUG_FATAL, msg, list);
            break;
        case SSL_DEBUG:
            SSL_DEBUGMSG(DEBUG_DEBUG, msg, list);
            break;
    }
    va_end(list);
}


/* Initializes or Deinitializes the SSL module. */
static unsigned int ssl_loaded = 0;
void ssl_init() {
    if(ssl_loaded) {
        ssl_msg(SSL_ERROR, "SSL: ssl_init(): called twice");
        return;
    }
    if(ssl_be_init()) {
        ssl_loaded = 1;
        ssl_msg(SSL_NOTICE, "SSL: ssl_init(): done");
    }
    else ssl_msg(SSL_ERROR, "SSL: ssl_be_deinit(): failed");
}
void ssl_deinit() {
    if(!ssl_loaded) {
        ssl_msg(SSL_ERROR, "SSL: ssl_deinit(): not initialized");
        return;
    }

    /* Check whether there are active SSL connections.
     * That is, the credentials-list must either be empty or contain only
     * one credential with ZERO references which then is deleted.
     */
    if((ssl_srv_credlist && (ssl_srv_credlist->next || ssl_srv_credlist->ref)) ||
       (ssl_cli_credlist && (ssl_cli_credlist->next || ssl_cli_credlist->ref))) {
        ssl_msg(SSL_ERROR, "SSL: ssl_deinit(): still active sessions");
        return;
    }
    if(ssl_srv_credlist) ssl_cred_free(ssl_srv_credlist);
    if(ssl_cli_credlist) ssl_cred_free(ssl_cli_credlist);

    ssl_be_deinit();
    ssl_clearcert();
    ssl_cleartrusts();

    ssl_msg(SSL_NOTICE, "SSL: ssl_deinit(): done");
    ssl_loaded = 0;
}


/* Creates/Frees a credential. */
ssl_cred_t *ssl_cred_new(unsigned int mode, char *cert, char **trusts) {
    ssl_cred_t *cred;

    cred = MyMalloc(sizeof(ssl_cred_t));
    memset(cred, 0, sizeof(ssl_cred_t));

    if(!ssl_be_cred_new(mode, cert, trusts, &cred->be)) {
        ssl_msg(SSL_ERROR, "SSL: ssl_be_cred_new(): failed.");
        MyFree(cred);
        return NULL;
    }

    if(mode == SSL_CLIENT) {
        if(ssl_cli_credlist && ssl_cli_credlist->ref == 0) ssl_cred_free(ssl_cli_credlist);
        cred->next = ssl_cli_credlist;
        ssl_cli_credlist = cred;
    }
    else {
        if(ssl_srv_credlist && ssl_srv_credlist->ref == 0) ssl_cred_free(ssl_srv_credlist);
        cred->next = ssl_srv_credlist;
        ssl_srv_credlist = cred;
    }
    cred->mode = mode;
    cred->ref = 0;
    ssl_msg(SSL_NOTICE, "SSL: ssl_cred_new(%u, '%s'): done", mode, cert);
    return cred;
}
void ssl_cred_free(ssl_cred_t *cred) {
    ssl_cred_t *iter;

    if(cred->ref) {
        ssl_msg(SSL_ERROR, "SSL: ssl_cred_free(%u, %u): still active sessions", cred->mode, cred->ref);
        return;
    }

    if(cred->mode == SSL_CLIENT) {
        iter = ssl_cli_credlist;
        if(iter == cred) {
            ssl_cli_credlist = iter->next;
            goto free_cred;
        }
        while(iter) {
            if(iter->next == cred) {
                iter->next = cred->next;
                goto free_cred;
            }
        }
        ssl_msg(SSL_ERROR, "SSL: ssl_cred_free(): invalid cred");
        return;
    }
    else {
        iter = ssl_srv_credlist;
        if(iter == cred) {
            ssl_srv_credlist = iter->next;
            goto free_cred;
        }
        while(iter) {
            if(iter->next == cred) {
                iter->next = cred->next;
                goto free_cred;
            }
        }
        ssl_msg(SSL_ERROR, "SSL: ssl_cred_free(): invalid cred");
        return;
    }

    free_cred:
    ssl_be_cred_free(&cred->be);
    ssl_msg(SSL_NOTICE, "SSL: ssl_cred_free(%u): done", cred->mode);
    MyFree(cred);
}


/* Manipulates an SSL session. */
ssl_session_t *ssl_session_new(unsigned int mode) {
    ssl_session_t *ssl;
    char **trusts, *fallback[1] = { NULL };

    /* If no SSL certificate is set, we stop.
     * We also clear \ssl_cert when allocating the certificate fails.
     * This prevents the ircd from reallocating the credentials everytime
     * a client connects although the allocation is guaranteed to fail.
     */
    if(!ssl_cert) return NULL;
    if(ssl_trusts) trusts = ssl_trusts;
    else trusts = fallback;

    ssl = MyMalloc(sizeof(ssl_session_t));
    memset(ssl, 0, sizeof(ssl_session_t));
    ssl->fingerprint = NULL;

    if(mode == SSL_CLIENT) {
        if(ssl_cli_credlist) ssl->cred = ssl_cli_credlist;
        else if(!(ssl->cred = ssl_cred_new(SSL_CLIENT, ssl_cert, trusts))) {
            MyFree(ssl_cert);
            ssl_cert = NULL;
            MyFree(ssl);
            ssl_msg(SSL_ERROR, "SSL: ssl_session_new(%u): failed", mode);
            return NULL;
        }
    }
    else {
        if(ssl_srv_credlist) ssl->cred = ssl_srv_credlist;
        else if(!(ssl->cred = ssl_cred_new(SSL_SERVER, ssl_cert, trusts))) {
            MyFree(ssl_cert);
            ssl_cert = NULL;
            MyFree(ssl);
            ssl_msg(SSL_ERROR, "SSL: ssl_session_new(%u): failed", mode);
            return NULL;
        }
    }

    if(!ssl_be_session_new(mode, &ssl->cred->be, &ssl->be)) {
        /* Keep credentials. They may be used later. */
        MyFree(ssl);
        ssl_msg(SSL_ERROR, "SSL: ssl_session_new(%u): failed", mode);
        return NULL;
    }

    ++ssl->cred->ref;
    ssl_msg(SSL_DEBUG, "SSL: ssl_session_new(%u): done", mode);
    return ssl;
}
void ssl_session_shutdown(ssl_session_t *ssl) {
    /* We do not care for the return value here. This might be implemented
     * in future. This makes ssl_shutdown() totally useless but this is only
     * a placeholder for future implementations.
     */
    ssl_be_session_shutdown(&ssl->be);
}
void ssl_session_free(ssl_session_t *ssl) {
    ssl_be_session_free(&ssl->be);

    /* Check whether to free the credentials. */
    if(--ssl->cred->ref == 0) {
        if(ssl_cli_credlist != ssl->cred && ssl_srv_credlist != ssl->cred) {
            ssl_cred_free(ssl->cred);
        }
    }

    ssl_msg(SSL_DEBUG, "SSL: ssl_session_free(%u): done", ssl->cred->mode);
    MyFree(ssl->fingerprint);
    MyFree(ssl);
}


/* This handles a new client connection. It puts the client into the SSL queue and
 * performs the SSL handshake. It either disconnects the client or passes the client
 * to add_connection() after the handshake has been performed.
 *
 * We use two callbacks. One for the timeout and one for the socket. To prevent that
 * both callbacks remove the ssl_pending_t structure or that they remove it too early
 * we remove the structure only when the socket has been set to -1. This security check
 * is needed, you should *NEVER* remove it.
 */
static void ssl_socket_callback(struct Event* ev) {
    struct ssl_pending_t *pend;
    unsigned int ret;

    pend = s_data(ev_socket(ev));
    switch(ev_type(ev)) {
        case ET_DESTROY:
            if(pend->fd == -1) MyFree(pend);
            return;
        case ET_ERROR:
        case ET_EOF:
            ssl_session_shutdown(pend->session);
            close(pend->fd);
            ssl_session_free(pend->session);
            socket_del(&pend->socket);
            timer_del(&pend->timeout);
            /* Set fd to -1 to make ET_DESTROY free "pend". */
            pend->fd = -1;
            return;
        case ET_READ:
        case ET_WRITE:
            /* Continue Handshake */
            ret = ssl_be_handshake(pend->session->cred->mode, &pend->session->be);
            if(ret == SSL_SUCCESS) {
                pend->session->fingerprint = strdup(ssl_be_fingerprint(&pend->session->be));
                timer_del(&pend->timeout);
                socket_del(&pend->socket);
                add_connection(pend->listener, pend->fd, pend->session);
                /* Set fd to -1 to make ET_DESTROY free "pend". */
                pend->fd = -1;
                return;
            }
            else if(ret == SSL_NEED_RD) {
                socket_events(&pend->socket, SOCK_ACTION_SET | SOCK_EVENT_READABLE);
                return;
            }
            else if(ret == SSL_NEED_WR || ret == SSL_NEED_RDWR) {
                socket_events(&pend->socket, SOCK_ACTION_SET | SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                return;
            }
            else /* SSL_FAILURE */ {
                ssl_session_shutdown(pend->session);
                close(pend->fd);
                ssl_session_free(pend->session);
                socket_del(&pend->socket);
                timer_del(&pend->timeout);
                /* Set fd to -1 to make ET_DESTROY free "pend". */
                pend->fd = -1;
                return;
            }
        default:
            return;
    }
}
static void ssl_timer_callback(struct Event* ev) {
    struct ssl_pending_t *pend;

    pend = t_data(ev_timer(ev));
    switch(ev_type(ev)) {
        case ET_DESTROY:
            /* Decrease refcount here because this is guaranteed to be called when the
             * connection gets destructed in any way.
             */
            --pend->listener->ref_count;
            /* Destruct \pend if required. */
            if(pend->fd == -1) MyFree(pend);
            return;
        case ET_EXPIRE:
            ssl_session_shutdown(pend->session);
            close(pend->fd);
            ssl_session_free(pend->session);
            socket_del(&pend->socket);
            timer_del(&pend->timeout);
            /* Set fd to -1 to make ET_DESTROY free "pend". */
            pend->fd = -1;
            return;
        default:
            return;
    }
}
void ssl_accept(struct Listener *listener, signed int fd) {
    unsigned int ret;
    struct ssl_pending_t *pend;

    if(!os_set_nonblocking(fd)) {
        close(fd);
        return;
    }
    os_disable_options(fd);

    pend = MyMalloc(sizeof(struct ssl_pending_t));
    pend->listener = listener;
    pend->fd = fd;
    pend->session = ssl_session_new(SSL_SERVER);

    if(!pend->session) {
        MyFree(pend);
        close(fd);
        ssl_msg(SSL_ERROR, "SSL: ssl_accept(%d): failed", fd);
        return;
    }

    if(!socket_add(&pend->socket, ssl_socket_callback, (void*)pend, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
        ssl_session_shutdown(pend->session);
        close(fd);
        ssl_session_free(pend->session);
        MyFree(pend);
        ssl_msg(SSL_ERROR, "SSL: ssl_accept(%d): failed", fd);
        return;
    }

    if(!ssl_be_session_connect(&pend->session->be, fd)) {
        socket_del(&pend->socket);
        ssl_session_shutdown(pend->session);
        close(fd);
        ssl_session_free(pend->session);
        MyFree(pend);
        ssl_msg(SSL_ERROR, "SSL: ssl_accept(%d): failed", fd);
        return;
    }

    ret = ssl_be_handshake(pend->session->cred->mode, &pend->session->be);
    if(ret == SSL_SUCCESS) {
        pend->session->fingerprint = strdup(ssl_be_fingerprint(&pend->session->be));
        socket_del(&pend->socket);
        add_connection(pend->listener, pend->fd, pend->session);
        MyFree(pend);
        return;
    }
    else if(ret == SSL_NEED_RD || ret == SSL_NEED_WR || ret == SSL_NEED_RDWR) {
        if(ret != SSL_NEED_RD) {
            socket_events(&pend->socket, SOCK_ACTION_SET | SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
        }
        timer_init(&pend->timeout);
        timer_add(&pend->timeout, ssl_timer_callback, (void*)pend, TT_RELATIVE, 20);
        ++listener->ref_count;
        return;
    }
    else /* SSL_FAILURE */ {
        socket_del(&pend->socket);
        ssl_session_shutdown(pend->session);
        close(fd);
        ssl_session_free(pend->session);
        MyFree(pend);
        ssl_msg(SSL_DEBUG, "SSL: ssl_accept(%d): failed", fd);
        return;
    }
}
static void ssl_csocket_callback(struct Event* ev) {
    struct ssl_conn_t *conn;
    unsigned int ret;

    conn = s_data(ev_socket(ev));
    switch(ev_type(ev)) {
        case ET_DESTROY:
            return;
        case ET_ERROR:
        case ET_EOF:
            cli_socket(conn->cptr).s_header.gh_call = client_sock_callback;
            s_data(&(cli_socket(conn->cptr))) = conn->olddata;
            ssl_session_free(conn->session);
            cli_socket(conn->cptr).ssl = NULL;
            exit_client_msg(conn->cptr, conn->cptr, &me, "SSL connection timedout.");
            sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL timeout.", cli_name(conn->cptr));
            conn->cptr = NULL;
            timer_del(&conn->timeout);
            return;
        case ET_READ:
        case ET_WRITE:
            /* Continue Handshake */
            ret = ssl_be_handshake(conn->session->cred->mode, &conn->session->be);
            if(ret == SSL_SUCCESS) {
                cli_socket(conn->cptr).s_header.gh_call = client_sock_callback;
                s_data(&(cli_socket(conn->cptr))) = conn->olddata;
                conn->session->fingerprint = strdup(ssl_be_fingerprint(&conn->session->be));
                if(completed_connection(conn->cptr) == 0) {
                    ssl_session_free(conn->session);
                    cli_socket(conn->cptr).ssl = NULL;
                    exit_client_msg(conn->cptr, conn->cptr, &me, "SSL handshake rejected.");
                }
                conn->cptr = NULL;
                timer_del(&conn->timeout);
                return;
            }
            else if(ret == SSL_NEED_RD) {
                socket_events(&cli_socket(conn->cptr), SOCK_ACTION_SET | SOCK_EVENT_READABLE);
                return;
            }
            else if(ret == SSL_NEED_WR || ret == SSL_NEED_RDWR) {
                socket_events(&cli_socket(conn->cptr), SOCK_ACTION_SET | SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                return;
            }
            else /* SSL_FAILURE */ {
                cli_socket(conn->cptr).s_header.gh_call = client_sock_callback;
                s_data(&(cli_socket(conn->cptr))) = conn->olddata;
                ssl_session_free(conn->session);
                cli_socket(conn->cptr).ssl = NULL;
                exit_client_msg(conn->cptr, conn->cptr, &me, "SSL connection timedout.");
                sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL timeout.", cli_name(conn->cptr));
                conn->cptr = NULL;
                timer_del(&conn->timeout);
                return;
            }
        default:
            return;
    }
}
static void ssl_ctimer_callback(struct Event* ev) {
    struct ssl_conn_t *conn;

    conn = t_data(ev_timer(ev));
    switch(ev_type(ev)) {
        case ET_DESTROY:
            if(conn->cptr == NULL) MyFree(conn);
            return;
        case ET_EXPIRE:
            cli_socket(conn->cptr).s_header.gh_call = client_sock_callback;
            s_data(&(cli_socket(conn->cptr))) = conn->olddata;
            ssl_session_free(conn->session);
            cli_socket(conn->cptr).ssl = NULL;
            exit_client_msg(conn->cptr, conn->cptr, &me, "SSL connection timedout.");
            sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL timeout.", cli_name(conn->cptr));
            conn->cptr = NULL;
            timer_del(&conn->timeout);
            return;
        default:
            return;
    }
}
signed int ssl_connect(struct Client *cptr) {
    struct ssl_conn_t *conn;
    unsigned int ret;
    signed int tmp;

    conn = MyMalloc(sizeof(struct ssl_conn_t));
    memset(conn, 0, sizeof(struct ssl_conn_t));

    conn->cptr = cptr;
    conn->session = ssl_session_new(SSL_CLIENT);
    cli_socket(cptr).ssl = conn->session;

    if(!conn->session) {
        cli_socket(cptr).ssl = NULL;
        MyFree(conn);
        ssl_msg(SSL_ERROR, "SSL: ssl_connect(): failed");
        sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL session-creation failed.", cli_name(cptr));
        return 0;
    }

    if(!ssl_be_session_connect(&conn->session->be, s_fd(&(cli_socket(cptr))))) {
        cli_socket(cptr).ssl = NULL;
        ssl_session_free(conn->session);
        MyFree(conn);
        ssl_msg(SSL_ERROR, "SSL: ssl_connect(): failed");
        sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL fd-connect failed.", cli_name(cptr));
        return 0;
    }

    ret = ssl_be_handshake(conn->session->cred->mode, &conn->session->be);
    if(ret == SSL_SUCCESS) {
        conn->session->fingerprint = strdup(ssl_be_fingerprint(&conn->session->be));
        tmp = completed_connection(cptr);
        MyFree(conn);
        return tmp;
    }
    else if(ret == SSL_NEED_RD || ret == SSL_NEED_WR || ret == SSL_NEED_RDWR) {
        if(ret == SSL_NEED_RD) {
            socket_events(&cli_socket(cptr), SOCK_ACTION_SET | SOCK_EVENT_READABLE);
        }
        else {
            socket_events(&cli_socket(cptr), SOCK_ACTION_SET | SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
        }
        /* Change callback temporarily to avoid ET_DESTROY on the old callback.
         * We will change this back before ET_DESTROY is called.
         */
        cli_socket(cptr).s_header.gh_call = ssl_csocket_callback;
        conn->olddata = s_data(&(cli_socket(cptr)));
        s_data(&(cli_socket(cptr))) = conn;
        timer_init(&conn->timeout);
        timer_add(&conn->timeout, ssl_ctimer_callback, (void*)conn, TT_RELATIVE, 20);
        return 1;
    }
    else /* SSL_FAILURE */ {
        cli_socket(cptr).ssl = NULL;
        ssl_session_free(conn->session);
        MyFree(conn);
        ssl_msg(SSL_ERROR, "SSL: ssl_connect(): failed");
        sendto_opmask_butone(0, SNO_OLDSNO, "Connection failed to %s: SSL handshake failed.", cli_name(cptr));
        return 0;
    }
    return 0;
}


/* Basic IO on SSL sockets. */
void ssl_close(signed int fd, ssl_session_t *ssl, const char *buf, unsigned int len) {
    if(!ssl) {
        write(fd, buf, len);
        close(fd);
    }
    else {
        ssl_be_send(fd, &ssl->be, buf, &len);
        ssl_session_shutdown(ssl);
        close(fd);
        ssl_session_free(ssl);
    }
}
signed int ssl_send(signed int fd, ssl_session_t *ssl, const char *buf, unsigned int len) {
    if(!ssl) {
        return write(fd, buf, len);
    }
    else {
        ssl_be_send(fd, &ssl->be, buf, &len);
        return len;
    }
}
IOResult ssl_recv(signed int fd, ssl_session_t *ssl, char *buf, unsigned int len, unsigned int *count_out) {
    if(!ssl) {
        return os_recv_nonb(fd, buf, len, count_out);
    }
    *count_out = len;
    return ssl_be_recv(fd, &ssl->be, buf, count_out);
}
IOResult ssl_sendv(signed int fd, ssl_session_t *ssl, struct MsgQ *buf, unsigned int *count_in, unsigned int *count_out) {
    #ifndef IOV_MAX
        #define IOV_MAX 16
    #endif /* IOV_MAX */
    signed int count;
    unsigned int k, tmp;
    struct iovec iov[IOV_MAX];
    IOResult ret = IO_BLOCKED, res;

    if(!ssl) {
        return os_sendv_nonb(fd, buf, count_in, count_out);
    }

    *count_in = 0;
    *count_out = 0;
    count = msgq_mapiov(buf, iov, IOV_MAX, count_in);

    for(k = 0; k < count; ++k) {
        tmp = iov[k].iov_len;
        res = ssl_be_send(fd, &ssl->be, iov[k].iov_base, &tmp);
        if(res == IO_FAILURE) return IO_FAILURE;
        else if(tmp == 0) return ret;
        else {
            *count_out += tmp;
            ret = IO_SUCCESS;
        }
    }
    return ret;
}
const char *ssl_cipherstr(ssl_session_t *ssl) {
    return ssl_be_cipherstr(&ssl->be);
}




/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/**********************            GnuTLS backend              *****************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/




#ifdef HAVE_GNUTLS
    unsigned int ssl_be_init() {
        signed int ret;
        if((ret = gnutls_global_init()) != GNUTLS_E_SUCCESS) {
            ssl_msg(SSL_ERROR, "SSL: gnutls_global_init(): failed (%d)", ret);
            return 0;
        }
        else return 1;
    }
    void ssl_be_deinit() {
        gnutls_global_deinit();
    }
    unsigned int ssl_be_cred_new(unsigned int mode, char *cert, char **trusts, ssl_be_cred_t *cred) {
        signed int ret;
        unsigned int i;
        if((ret = gnutls_dh_params_init(&cred->dhparams)) != GNUTLS_E_SUCCESS) {
            ssl_msg(SSL_ERROR, "SSL: gnutls_dh_params_init(): failed (%d)", ret);
            return 0;
        }
        if((ret = gnutls_dh_params_generate2(cred->dhparams, SSL_DH_BITS)) != GNUTLS_E_SUCCESS) {
            gnutls_dh_params_deinit(cred->dhparams);
            ssl_msg(SSL_ERROR, "SSL: gnutls_dh_params_generate2(): failed (%d)", ret);
            return 0;
        }
        if((ret = gnutls_certificate_allocate_credentials(&cred->cred)) != GNUTLS_E_SUCCESS) {
            gnutls_dh_params_deinit(cred->dhparams);
            ssl_msg(SSL_ERROR, "SSL: gnutls_certificate_allocate_credentials(): failed (%d)", ret);
            return 0;
        }
        i = 0;
        while(trusts[i]) {
            if((ret = gnutls_certificate_set_x509_trust_file(cred->cred, trusts[i], GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
                ssl_msg(SSL_NOTICE, "SSL: gnutls_certificate_set_x509_trust_file('%s'): failed (%d)", trusts[i], ret);
                /* ignore errors here */
            }
            ++i;
        }
        if((ret = gnutls_certificate_set_x509_key_file(cred->cred, cert, cert, GNUTLS_X509_FMT_PEM)) != GNUTLS_E_SUCCESS) {
            gnutls_certificate_free_credentials(cred->cred);
            gnutls_dh_params_deinit(cred->dhparams);
            ssl_msg(SSL_NOTICE, "SSL: gnutls_certificate_set_x509_key_file('%s'): failed (%d)", cert, ret);
            return 0;
        }
        gnutls_certificate_set_dh_params(cred->cred, cred->dhparams);
        gnutls_priority_init(&cred->prio, "NORMAL", NULL);
        return 1;
    }
    void ssl_be_cred_free(ssl_be_cred_t *cred) {
        gnutls_certificate_free_credentials(cred->cred);
        gnutls_priority_deinit(cred->prio);
        gnutls_dh_params_deinit(cred->dhparams);
    }
    unsigned int ssl_be_session_new(unsigned int mode, ssl_be_cred_t *cred, ssl_be_session_t *session) {
        signed int ret;
        if(mode == SSL_CLIENT) {
            if((ret = gnutls_init(session, GNUTLS_CLIENT)) != GNUTLS_E_SUCCESS) {
                ssl_msg(SSL_ERROR, "SSL: gnutls_init(): failed (%d)", ret);
                return 0;
            }
            gnutls_priority_set(*session, cred->prio);
            /*if((ret = gnutls_priority_set_direct(*session, "NORMAL", NULL)) != GNUTLS_E_SUCCESS) {
                gnutls_deinit(*session);
                ssl_msg(SSL_ERROR, "SSL: gnutls_priority_set_direct(): failed (%d)", ret);
                return 0;
            }*/
            if((ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cred->cred)) != GNUTLS_E_SUCCESS) {
                gnutls_deinit(*session);
                ssl_msg(SSL_ERROR, "SSL: gnutls_credentials_set(): failed (%d)", ret);
                return 0;
            }
            gnutls_dh_set_prime_bits(*session, SSL_DH_RBITS);
        }
        else {
            if((ret = gnutls_init(session, GNUTLS_SERVER)) != GNUTLS_E_SUCCESS) {
                ssl_msg(SSL_ERROR, "SSL: gnutls_init(): failed (%d)", ret);
                return 0;
            }
            gnutls_priority_set(*session, cred->prio);
            /*if((ret = gnutls_priority_set_direct(*session, "NORMAL", NULL)) != GNUTLS_E_SUCCESS) {
                gnutls_deinit(*session);
                ssl_msg(SSL_ERROR, "SSL: gnutls_priority_set_direct(): failed (%d)", ret);
                return 0;
            }*/
            if((ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cred->cred)) != GNUTLS_E_SUCCESS) {
                gnutls_deinit(*session);
                ssl_msg(SSL_ERROR, "SSL: gnutls_credentials_set(): failed (%d)", ret);
                return 0;
            }
            gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUEST);
        }
        return 1;
    }
    unsigned int ssl_be_session_connect(ssl_be_session_t *session, signed int fd) {
        gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t)fd);
        return 1;
    }
    void ssl_be_session_shutdown(ssl_be_session_t *session) {
        gnutls_bye(*session, GNUTLS_SHUT_WR);
    }
    void ssl_be_session_free(ssl_be_session_t *session) {
        gnutls_deinit(*session);
    }
    unsigned int ssl_be_handshake(unsigned int mode, ssl_be_session_t *session) {
        signed int ret;
        ret = gnutls_handshake(*session);
        if(ret < 0) {
            if(ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
                if(gnutls_record_get_direction(*session) == 0) return SSL_NEED_RD;
                else return SSL_NEED_WR;
            }
            else {
                ssl_msg(SSL_DEBUG, "SSL: gnutls_handshake(): failed (%d)", ret);
                return SSL_FAILURE;
            }
        }
        else return SSL_SUCCESS;
    }
    const char *ssl_be_cipherstr(ssl_be_session_t *session) {
        static char buf[401];
        const char *kx_name, *cipher_name, *mac_name;
        unsigned int len, i;
        char *dest;

        kx_name = gnutls_kx_get_name(gnutls_kx_get(*session));
        cipher_name = gnutls_cipher_get_name(gnutls_cipher_get(*session));
        mac_name = gnutls_mac_get_name(gnutls_mac_get(*session));

        if(!kx_name || !cipher_name || !mac_name) {
            ssl_msg(SSL_ERROR, "SSL: gnutls_[kx,cipher,mac]_get_name(): failed");
            return "<invalid>";
        }

        len = strlen(kx_name) + strlen(cipher_name) + strlen(mac_name);
        if(len > 395) {
            ssl_msg(SSL_ERROR, "SSL: gnutls_[kx,cipher,mac]_get_name(): too long");
            return "<invalid>";
        }
        else {
            dest = buf;
            i = 0;
            while((*dest++ = kx_name[i++])) /* empty */ ;
            *(dest - 1) = '-';
            i = 0;
            while((*dest++ = cipher_name[i++])) /* empty */ ;
            *(dest - 1) = '-';
            i = 0;
            while((*dest++ = mac_name[i++])) /* empty */ ;
            return buf;
        }
    }
    const char *ssl_be_fingerprint(ssl_be_session_t *session) {
        return "<invalid>";
    }
    IOResult ssl_be_send(signed int fd, ssl_be_session_t *ssl, const char *buf, unsigned int *count_out) {
        signed int res;
        res = gnutls_record_send(*ssl, buf, *count_out);
        *count_out = 0;
        if(res == 0) return IO_FAILURE;
        else if(res < 0) {
            if(res != GNUTLS_E_AGAIN && res != GNUTLS_E_INTERRUPTED) return IO_FAILURE;
            else return IO_BLOCKED;
        }
        else {
            *count_out = res;
            return IO_SUCCESS;
        }
    }
    IOResult ssl_be_recv(signed int fd, ssl_be_session_t *ssl, char *buf, unsigned int *count_out) {
        signed int res;
        res = gnutls_record_recv(*ssl, buf, *count_out);
        *count_out = 0;
        if(res == 0) return IO_FAILURE;
        else if(res < 0) {
            if(res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) return IO_BLOCKED;
            else return IO_FAILURE;
        }
        else {
            *count_out = res;
            return IO_SUCCESS;
        }
    }




/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/**********************            OpenSSL backend             *****************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/




#elif defined(HAVE_OPENSSL)
    unsigned int ssl_be_init() {
        SSL_library_init();
        /* Load error strings; Returns void. */
        SSL_load_error_strings();
        /* Seed the random number generator. We do not care for errors here. */
        RAND_load_file("/dev/urandom", 4096);
        return 1;
    }
    void ssl_be_deinit() {
        ERR_free_strings();
    }
    unsigned int ssl_be_cred_new(unsigned int mode, char *cert, char **trusts, ssl_be_cred_t *cred) {
        if(mode == SSL_CLIENT) {
            *cred = SSL_CTX_new(SSLv23_client_method());
            if(!*cred) {
                ssl_msg(SSL_ERROR, "SSL: SSL_CTX_new(): failed");
                return 0;
            }
            if(*trusts) {
                if(*(trusts + 1)) ssl_msg(SSL_NOTICE, "SSL: (OpenSSL) skipping further CA files");
                if(!SSL_CTX_load_verify_locations(*cred, *trusts, NULL)) {
                    ssl_msg(SSL_NOTICE, "SSL: SSL_CTX_load_verify_locations('%s'): failed", *trusts);
                    /* ignore errors here */
                }
                else SSL_CTX_set_client_CA_list(*cred, SSL_load_client_CA_file(*trusts));
            }
            SSL_CTX_set_mode(*cred, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            if(!SSL_CTX_use_certificate_file(*cred, cert, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(*cred);
                ssl_msg(SSL_NOTICE, "SSL: SSL_CTX_use_certificate_file('%s'): failed", cert);
                return 0;
            }
            if(!SSL_CTX_use_PrivateKey_file(*cred, cert, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(*cred);
                ssl_msg(SSL_NOTICE, "SSL: SSL_CTX_use_PrivateKey_file('%s'): failed", cert);
                return 0;
            }
            SSL_CTX_set_verify(*cred, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_be_verify);
        }
        else {
            *cred = SSL_CTX_new(SSLv23_server_method());
            if(!*cred) {
                ssl_msg(SSL_ERROR, "SSL: SSL_CTX_new(): failed");
                return 0;
            }
            SSL_CTX_set_mode(*cred, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            if(!SSL_CTX_use_certificate_file(*cred, cert, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(*cred);
                ssl_msg(SSL_NOTICE, "SSL: SSL_CTX_use_certificate_file('%s'): failed", cert);
                return 0;
            }
            if(!SSL_CTX_use_PrivateKey_file(*cred, cert, SSL_FILETYPE_PEM)) {
                SSL_CTX_free(*cred);
                ssl_msg(SSL_NOTICE, "SSL: SSL_CTX_use_PrivateKey_file('%s'): failed", cert);
                return 0;
            }
        }
        return 1;
    }
    void ssl_be_cred_free(ssl_be_cred_t *cred) {
        SSL_CTX_free(*cred);
    }
    unsigned int ssl_be_session_new(unsigned int mode, ssl_be_cred_t *cred, ssl_be_session_t *session) {
        *session = SSL_new(*cred);
        if(!*session) {
            ssl_msg(SSL_ERROR, "SSL: SSL_new(%u): failed", mode);
            return 0;
        }
        return 1;
    }
    unsigned int ssl_be_session_connect(ssl_be_session_t *session, signed int fd) {
        SSL_set_fd(*session, fd);
        return 1;
    }
    void ssl_be_session_shutdown(ssl_be_session_t *session) {
        SSL_shutdown(*session);
    }
    void ssl_be_session_free(ssl_be_session_t *session) {
        SSL_free(*session);
    }
    unsigned int ssl_be_handshake(unsigned int mode, ssl_be_session_t *session) {
        signed int ret;
        if(mode == SSL_CLIENT) ret = SSL_connect(*session);
        else ret = SSL_accept(*session);
        if(ret <= 0) {
            ret = SSL_get_error(*session, ret);
            if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
                if(ret == SSL_ERROR_WANT_READ) return SSL_NEED_RD;
                else return SSL_NEED_WR;
            }
            else {
                ssl_msg(SSL_DEBUG, "SSL: gnutls_handshake(): failed (%d)", ret);
                return SSL_FAILURE;
            }
        }
        else return SSL_SUCCESS;
    }
    const char *ssl_be_cipherstr(ssl_be_session_t *session) {
        static char buf[400];
        char buf2[128];
        int bits;
        SSL_CIPHER *c;

        buf[0] = '\0';
        strcpy(buf, SSL_get_version(*session));
        strcat(buf, "-");
        strcat(buf, SSL_get_cipher(*session));
        c = SSL_get_current_cipher(*session);
        SSL_CIPHER_get_bits(c, &bits);
        strcat(buf, "-");
        ircd_snprintf(0, buf2, sizeof(buf2), "%d", bits);
        strcat(buf, buf2);
        strcat(buf, "bits");
        return buf;
    }
    const char *ssl_be_fingerprint(ssl_be_session_t *session) {
        return "<invalid>";
    }
    IOResult ssl_be_send(signed int fd, ssl_be_session_t *ssl, const char *buf, unsigned int *count_out) {
        signed int res, merrno;

#ifdef SSL_EAGAIN_DEBUG
        signed int back, back_c;
        char buffer[4097];
#endif

        res = SSL_write(*ssl, buf, *count_out);
        merrno = errno;

#ifdef SSL_EAGAIN_DEBUG
        back_c = *count_out;
#endif

        *count_out = 0;
        if(res == 0) return IO_FAILURE;
        else if(res < 0) {
#ifdef SSL_EAGAIN_DEBUG
            back = res;
#endif
            res = SSL_get_error(*ssl, res);
            /* HACK HACK HACK!
             * OpenSSL sucks! This hack still returns IO_BLOCKED on special SYSCALL failures.
             * The ircd system is built that the user will be killed automatically when this
             * happens too often so we can safely return this here, however, the OpenSSL devs
             * should *REALLY* fix this. They're already noticed.
             * --gix
             */
            if(res != SSL_ERROR_WANT_READ && res != SSL_ERROR_WANT_WRITE && res != SSL_ERROR_WANT_X509_LOOKUP) {
                if(merrno == EAGAIN || merrno == EINTR || merrno == EWOULDBLOCK || merrno == EBUSY) {
#ifdef SSL_EAGAIN_DEBUG
                    snprintf(buffer, (back_c > 4096)?4096:back_c, "%s", buf);
                    buffer[4096] = 0;
                    ssl_msg(SSL_NOTICE, "OpenSSL: EAGAIN debug information: fd (%d) err (%d) serr (%d) "
                                        "derr1 (%lu) derr2 (%lu) back (%d) len (%u) buf (%s)",
                                        fd, merrno, res, ERR_peek_error(), ERR_peek_last_error(), back, back_c, buffer);
#endif
                    return IO_BLOCKED;
                }
                return IO_FAILURE;
            }
            else return IO_BLOCKED;
        }
        else {
            *count_out = res;
            return IO_SUCCESS;
        }
    }
    IOResult ssl_be_recv(signed int fd, ssl_be_session_t *ssl, char *buf, unsigned int *count_out) {
        signed int res, merrno;
        res = SSL_read(*ssl, buf, *count_out);
        merrno = errno;
        *count_out = 0;
        if(res == 0) return IO_FAILURE;
        else if(res < 0) {
            res = SSL_get_error(*ssl, res);
            if(res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE || res == SSL_ERROR_WANT_X509_LOOKUP) return IO_BLOCKED;
            /* HACK HACK HACK!
             * OpenSSL sucks! This hack still returns IO_BLOCKED on special SYSCALL failures.
             * The ircd system is built that the user will be killed automatically when this
             * happens too often so we can safely return this here, however, the OpenSSL devs
             * should *REALLY* fix this. They're already noticed.
             * --gix
             */
            else if(merrno == EAGAIN || merrno == EINTR || merrno == EWOULDBLOCK || merrno == EBUSY) return IO_BLOCKED;
            else return IO_FAILURE;
        }
        else {
            *count_out = res;
            return IO_SUCCESS;
        }
    }
    static signed int ssl_be_verify(signed int preverify_ok, X509_STORE_CTX *ctx) {
        return 1;
    }




/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/**********************             Dummy backend              *****************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/
/*******************************************************************************/




#else
    unsigned int ssl_be_init() {
        return 1;
    }
    void ssl_be_deinit() {
        return;
    }
    unsigned int ssl_be_cred_new(unsigned int mode, char *cert, char **trusts, ssl_be_cred_t *cred) {
        *cred = NULL;
        return 1;
    }
    void ssl_be_cred_free(ssl_be_cred_t *cred) {
        return;
    }
    unsigned int ssl_be_session_new(unsigned int mode, ssl_be_cred_t *cred, ssl_be_session_t *session) {
        *session = NULL;
        return 1;
    }
    unsigned int ssl_be_session_connect(ssl_be_session_t *session, signed int fd) {
        return 1;
    }
    void ssl_be_session_shutdown(ssl_be_session_t *session) {
        return;
    }
    void ssl_be_session_free(ssl_be_session_t *session) {
        return;
    }
    unsigned int ssl_be_handshake(unsigned int mode, ssl_be_session_t *session) {
        return SSL_FAILURE;
    }
    const char *ssl_be_cipherstr(ssl_be_session_t *session) {
        return "PLAINTEXT";
    }
    const char *ssl_be_fingerprint(ssl_be_session_t *session) {
        return "<invalid>";
    }
    IOResult ssl_be_send(signed int fd, ssl_be_session_t *ssl, const char *buf, unsigned int *count_out) {
        return IO_FAILURE;
    }
    IOResult ssl_be_recv(signed int fd, ssl_be_session_t *ssl, char *buf, unsigned int *count_out) {
        return IO_FAILURE;
    }
#endif

