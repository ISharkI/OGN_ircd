/*
 * IRC - Internet Relay Chat, ircd/m_svsnick.c
 * Written by David Herrmann.
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_features.h"
#include "ircd_crypt.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"
#include "s_misc.h"
#include "match.h"
#include "IPcheck.h"
#include "ssl.h"
#include "res.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Sends response \r (len: \l) to client \c. */
#define webirc_resp(c, r, l) \
   ssl_send(cli_fd(c), cli_socket(c).ssl, r, l)

/* Buffer used in nick replacements. */
static char webirc_buf[513];

/* Returns 1 if the passwords are the same and 0 if not.
 * \to_match is the password hash
 * \passwd is the unhashed password in "$KIND$password" style
 */
static unsigned int webirc_pwmatch(const char* to_match, const char* passwd) {
    char *crypted;
    signed int res;

    crypted = ircd_crypt(to_match, passwd);
    if(!crypted)
        return 0;
    res = strcmp(crypted, passwd);
    MyFree(crypted);
    return 0 == res;
}

/* Checks whether password/host/spoofed host/ip are allowed and returns the corresponding webirc block.
 * Returns NULL if nothing found.
 */
static struct webirc_block *webirc_match(const char *passwd, const char *real_host, const char *real_ip, const char *spoofed_host, const char *spoofed_ip) {
    struct webirc_block *iter;
    struct webirc_node *inode;
    unsigned int matched = 0;

    if(!GlobalWebIRCConf) return NULL;

    iter = GlobalWebIRCConf;
    do {
        if(iter->list) {
            inode = iter->list;

            /* first check for matching password */
            do {
                /* it's a sorted list an passwords are stored first! */
                if(inode->type != WEBIRC_PASS) break;

                if(webirc_pwmatch(passwd, inode->content)) {
                    matched = 1;
                    break;
                }

                inode = inode->next;
            } while(inode != iter->list);

            /* go to next entry */
            inode = inode->next;

            /* check for matching real-host/ip */
            if(matched) {
                matched = 0;
                /* fast-forward to hosts and then check the hosts */
                do {
                    /* everything greater than WEBIRC_HOSTS are the spoofed masks */
                    if(inode->type > WEBIRC_HOST) break;

                    if(inode->type == WEBIRC_HOST) {
                        if(inode->neg) {
                            if(match(inode->content, real_host) == 0 || match(inode->content, real_ip) == 0) {
                                matched = 0;
                                break;
                            }
                        }
                        else if(matched) /* do nothing */;
                        else if(match(inode->content, real_host) == 0 || match(inode->content, real_ip) == 0)
                            matched = 1;
                    }

                    inode = inode->next;
                } while(inode != iter->list);
            }

            /* check for matching spoofed host/ip */
            if(matched) {
                matched = 0;
                do {
                    if(inode->type == WEBIRC_SPOOF) {
                        if(inode->neg) {
                            if(match(inode->content, spoofed_host) == 0 || match(inode->content, spoofed_ip) == 0) {
                                matched = 0;
                                break;
                            }
                        }
                        else if(matched) /* do nothing */;
                        else if(match(inode->content, spoofed_host) == 0 || match(inode->content, spoofed_ip) == 0)
                            matched = 1;
                    }

                    inode = inode->next;
                } while(inode != iter->list);
            }

            if(matched) return iter;

            /* nothing found, try next block */
        }
        iter = iter->next;
    } while(iter != GlobalWebIRCConf);

    return NULL;
}

/*
 * m_webirc
 *
 * parv[0] = sender prefix
 * parv[1] = password
 * parv[2] = "cgiirc"
 * parv[3] = hostname
 * parv[4] = ip
 */
int m_webirc(struct Client* cptr, struct Client* sptr, int parc, char* parv[]) {
    struct webirc_block *block;
    struct irc_in_addr addr;
    const char *con_addr;
    time_t next_target = 0;
    unsigned int len;

    const char *nick = (*(cli_name(sptr))) ? cli_name(sptr) : "AUTH";
    unsigned int auth = (*(cli_name(sptr))) ? 0 : 1;

    /* servers cannot spoof their ip */
    if(IsServerPort(sptr)) {
        /* If a server sends WEBIRC command it's a protocol violation so exit him and do not check FEAT_WEBIRC_REJECT. */
        IPcheck_connect_fail(sptr);
        return exit_client(cptr, sptr, &me, "WebIRC not supported on server ports");
    }

    /* all 4 parameters are required plus the prefix => 5 */
    if(parc < 5)
        return need_more_params(sptr, "WEBIRC");

    if(strcmp(parv[2], "cgiirc")) {
        if(feature_bool(FEAT_WEBIRC_REJECT)) {
            IPcheck_connect_fail(sptr);
            return exit_client(cptr, sptr, &me, "WebIRC protocol violation (p2).");
        }
        else {
            len = sprintf(webirc_buf, "NOTICE %s :%sWebIRC protocol violation (p2).\r\n", nick, auth ? "*** " : "");
            webirc_resp(sptr, webirc_buf, len);
            return 0; /* continue with normal authentication */
        }
    }

    /* created ip in dotted notation */
    con_addr = ircd_ntoa(&(cli_ip(sptr)));
    if(0 == ipmask_parse(parv[4], &addr, NULL)) {
        if(feature_bool(FEAT_WEBIRC_REJECT)) {
            IPcheck_connect_fail(sptr);
            return exit_client(cptr, sptr, &me, "WebIRC protocol violation (p4).");
        }
        else {
            /* bufferoverflow prevented with NICKLEN check above */
            len = sprintf(webirc_buf, "NOTICE %s :%sWebIRC protocol violation (p4).\r\n", nick, auth ? "*** " : "");
            webirc_resp(sptr, webirc_buf, len);
            return 0; /* continue with normal authentication */
        }
    }

    /* find matching webirc block */
    block = webirc_match(parv[1], cli_sockhost(sptr), con_addr, parv[3], parv[4]);
    if(!block) {
        if(feature_bool(FEAT_WEBIRC_REJECT)) {
            IPcheck_connect_fail(sptr);
            return exit_client(cptr, sptr, &me, "WebIRC client rejected, no match found.");
        }
        else {
            len = sprintf(webirc_buf, "NOTICE %s :%sWebIRC spoofing rejected, no match found.\r\n", nick, auth?"*** ":"");
            webirc_resp(sptr, webirc_buf, len);
            return 0; /* continue with normal authentication */
        }
    }

    /* remove the WebIRC ip from the IPcheck entry, we will add the real one later */
    IPcheck_connect_fail(sptr);
    IPcheck_disconnect(sptr);
    ClearIPChecked(sptr);

    /* spoof IP */
    memcpy(cli_real_ip(sptr).in6_16, cli_ip(sptr).in6_16, 16);
    memcpy(cli_ip(sptr).in6_16, addr.in6_16, 16);

    /* spoof ip/host strings */
    ircd_strncpy(cli_real_sock_ip(sptr), cli_sock_ip(sptr), SOCKIPLEN);
    ircd_strncpy(cli_sock_ip(sptr), parv[4], SOCKIPLEN);
    ircd_strncpy(cli_real_sockhost(sptr), cli_sockhost(sptr), HOSTLEN);
    ircd_strncpy(cli_sockhost(sptr), parv[3], HOSTLEN);
    ircd_strncpy(cli_webirc(sptr), block->name, NICKLEN);

    /* add the real ip to the IPcheck */
    if(!IPcheck_local_connect(&cli_ip(sptr), &next_target))
        return exit_client(cptr, sptr, &me, "Too many connections from your host");
    SetIPChecked(cptr);

    /* set WebIRC umode only if enabled */
    if(feature_bool(FEAT_WEBIRC_UMODE))
        SetWebIRC(cptr);

    return 0;
}

