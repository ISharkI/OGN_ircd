/*
 * IRC - Internet Relay Chat, ircd/m_relay.c
 * Written by David Herrmann.
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static void loc_handler_LR(const char *num) {
    if(num[0] != '!') return;
    auth_loc_reply(&num[3], NULL, NULL);
}

static void loc_handler_LA(const char *num, char *parv[], signed int parc) {
    if(num[0] != '!' || parc < 1) return;
    if(parc > 1)
        auth_loc_reply(&num[3], parv[0], parv[1]);
    else
        auth_loc_reply(&num[3], parv[0], NULL);
}

/** RELAY
 * The RELAY command has a special purpose. It is always built the following way:
 *  <sender> RELAY <destination> <command>[ <list of parameters>]
 * The <sender> is a single numeric nick of a server or user. <destination> can be:
 * - a numeric-nick of a server (2 characters long): eg., AD
 * - a numeric-nick of a user (5 characters long): eg., ADAAB
 * - a numeric-nick of an unregistered user (6 characters long): eg., !ADAAB
 * <command> is a subcommdn of RELAY.
 *
 * If we receive such a message, we relay the message to the server of <destination>.
 * If we are the target, we check <command> and call the related subcommand handler.
 *
 * Therefore, this interface can be used to relay messages through the network without
 * specifying new commands.
 */
/* ms_relay - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target
 * parv[2] = subcommand
 * parv[3-X] = NULL or a list of parameters.
 */
signed int ms_relay(struct Client* cptr, struct Client* sptr, signed int parc, char* parv[]) {
    struct Client *server;
    unsigned int len, i;
    char buf[3], *act, *m, buffer[513];

    if(parc < 3) {
        return protocol_violation(cptr, "Too few arguments for RELAY");
    }

    /* Check <destination>. */
    len = strlen(parv[1]);
    buf[2] = 0;
    switch(len) {
        case 2:
            server = FindNServer(parv[1]);
            break;
        case 5:
            buf[0] = parv[1][0];
            buf[1] = parv[1][1];
            server = FindNServer(buf);
            break;
        case 6:
            buf[0] = parv[1][1];
            buf[1] = parv[1][2];
            server = FindNServer(buf);
            break;
        default:
            /* Invalid destination. Ignore. */
            return 0;
    }

    if(server != &me) {
        if(parc > 3) {
            act = buffer;
            for(i = 3; i < (parc - 1); ++i) {
                m = parv[i];
                while((*act++ = *m++)) /* empty loop */ ;
                *(act - 1) = ' ';
            }
            m = parv[i];
            *act++ = ':';
            while((*act++ = *m++)) /* empty loop */ ;
            sendcmdto_one(sptr, CMD_RELAY, server, "%s %s %s", parv[1], parv[2], buffer);
        }
        else sendcmdto_one(sptr, CMD_RELAY, server, "%s %s", parv[1], parv[2]);
        return 0;
    }

    /* Call subcommand handler. */
    if(strcmp("LR", parv[2]) == 0) loc_handler_LR(parv[1]);
    else if(strcmp("LA", parv[2]) == 0 && parc > 3) loc_handler_LA(parv[1], &parv[3], parc - 3);

    return 0;
}

