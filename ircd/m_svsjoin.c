/*
 * IRC - Internet Relay Chat, ircd/m_svsjoin.c
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
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/** SVSJOIN
 * SVSJOIN is forwarded to the server where the user is connected to.
 * This allows to send SVSJOINs from all servers in the network but additionally causes
 * some overhead. Though, SVSJOIN is not often called and this overhead can be ignored.
 */
/* ms_svsjoin - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = numeric of client
 * parv[2] = channel, NO CHANLIST!
 */
signed int ms_svsjoin(struct Client* cptr, struct Client* sptr, signed int parc, char* parv[]) {
    struct Client *acptr;
    struct Channel *chptr;
    struct JoinBuf join;
    struct JoinBuf create;
    unsigned int flags = 0;
    char *name;

    if(parc < 3) {
        return protocol_violation(cptr, "Too few arguments for SVSJOIN");
    }

    /* Ignore if the user has already quitted. */
    if(!(acptr = findNUser(parv[1]))) {
        return 0;
    }

    /* Check channelname. */
    if(!IsChannelName(parv[2]) || !strIsIrcCh(parv[2])) {
        return 0;
    }

    /* Create channel if necessary and return a pointer. */
    chptr = get_channel(acptr, parv[2], (!FindChannel(parv[2])) ? CGT_CREATE : CGT_NO_CREATE);
    if(find_member_link(chptr, acptr)) return 0; /* User is already in the channel. */

    /* Forward the message to the server where the user is connected to. */
    if(!MyConnect(acptr)) {
        sendcmdto_one(sptr, CMD_SVSJOIN, acptr, "%s %s", parv[1], chptr->chname);
        return 0;
    }

    name = chptr->chname;

    /* We need to use \joinbuf to let a user join.
     * We fill only the \joinbuf which is actually used but
     * create both.
     */

    joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
    joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());

    flags = (chptr->users == 0) ? CHFL_CHANOP : CHFL_DEOPPED;
    if(chptr) joinbuf_join(&join, chptr, flags);
    else joinbuf_join(&create, chptr, flags);

    /* Send information to the user. */
    if(chptr->topic[0]) {
        send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
        send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick, chptr->topic_time);
    }
    do_names(acptr, chptr, NAMES_ALL|NAMES_EON);

    joinbuf_flush(&join);
    joinbuf_flush(&create);

    return 0;
}

