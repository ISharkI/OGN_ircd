/*
 * IRC - Internet Relay Chat, ircd/m_check.c
 * Written by David Herrmann.
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define COLOR_OFF '\017'

void checkChannel(struct Client *sptr, struct Channel *chptr);
void checkUsers(struct Client *sptr, struct Channel *chptr, int flags);
void checkClient(struct Client *sptr, struct Client *acptr, int flags);
void checkServer(struct Client *sptr, struct Client *acptr);

static int checkClones(struct Channel *chptr, char *nick, char *host) {
    int clones = 0;
    struct Membership *lp;
    struct Client *acptr;

    for(lp = chptr->members; lp; lp = lp->next_member) {
        acptr = lp->user;
        if(!strcmp(acptr->cli_user->realhost, host) && strcmp(acptr->cli_name, nick)) clones++;
    }

    return ((clones) ? clones + 1 : 0);
}

/* This /check implementation is based on several other ircds. All of them
 * are licensed under the GPL.
 * The following comments are from each implementation.
 * --gix
 */
/** ASUKA
 * This is the implementation of the CHECK function for Asuka.
 * Some of this code is from previous QuakeNet ircds, but most of it is mine..
 * The old code was written by Durzel (durzel@quakenet.org).
 *
 * qoreQ (qoreQ@quakenet.org) - 08/14/2002
 */
/** IRCPlanet
 * Modified by falcon for ircu2.10.12-ircplanet
 *
 * Dominik Paulus - 2007/05/12
 */
/** IRCu Patchset
 * Modified by gix for the IRCu-Patchset.
 *
 * David Herrmann - 2009/03/09
 */

#define CHECK_CHECKCHAN 0x01 /* -c */
#define CHECK_SHOWUSERS 0x02 /* ! -u */
#define CHECK_OPSONLY   0x04 /* -o */
#define CHECK_SHOWIPS   0x08 /* -i */

/*
 * Syntax: CHECK <channel|nick|server> [-flags]
 *
 * Where valid flags are:
 * -c: Show channels when checking a user even if the user is on more than 50 channels.
 * -i: Show IPs instead of hostnames when displaying results.
 * -o: Only show channel operators when checking a channel.
 * -u: Hide users when checking a channel. Overrides -o.
 */
/*
 * m_check()
 * generic message handler
 */
int mo_check(struct Client *cptr, struct Client *sptr, int parc, char *parv[]) {
    struct Channel *chptr;
    struct Client *acptr;
    int i, flags = CHECK_SHOWUSERS;

    if(!IsXtraOp(sptr))
        return send_reply(sptr, ERR_NOPRIVILEGES);

    if(parc < 2)
        return send_reply(sptr, ERR_NEEDMOREPARAMS, "CHECK");

    /* This checks to see if any flags have been supplied */
    if((parc > 2) && (parv[2][0] == '-')) {
        for(i = 1; parv[2][i]; ++i) {
            switch (parv[2][i]) {
                case 'c':
                    flags |= CHECK_CHECKCHAN;
                    break;
                case 'o':
                    if(flags & CHECK_SHOWUSERS)
                        flags |= CHECK_OPSONLY;
                    break;
                case 'u':
                    flags &= ~(CHECK_SHOWUSERS | CHECK_OPSONLY);
                    break;
                case 'i':
                    flags |= CHECK_SHOWIPS;
                    break;
            }
        }
    }

    if((chptr = FindChannel(parv[1]))) {
        checkChannel(sptr, chptr);
        checkUsers(sptr, chptr, flags);
    }
    else if((acptr = FindUser(parv[1]))) {
        if(!IsRegistered(acptr))
            return send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);
        checkClient(sptr, acptr, flags);
    }
    else if((acptr = FindServer(parv[1])))
        checkServer(sptr, acptr);
    else send_reply(sptr, ERR_SEARCHNOMATCH, "CHECK", parv[1]);

    return 1;
}

void checkServer(struct Client *sptr, struct Client *acptr) {
    char outbuf[BUFSIZE];
    int dlinkc = 0;
    struct DLink* slink = NULL;

    /* Header */
    send_reply(sptr, RPL_CHKHEAD, "server", acptr->cli_name);
    send_reply(sptr, RPL_DATASTR, " ");

    ircd_snprintf(0, outbuf, sizeof(outbuf), "   Connected at: %s", myctime(acptr->cli_serv->timestamp));
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "    Server name: %s", acptr->cli_name);
    send_reply(sptr, RPL_DATASTR,  outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "        Numeric: %s --> %d", NumServ(acptr), base64toint(acptr->cli_yxx));
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "          Users: %d / %d", cli_serv(acptr)->clients, base64toint(cli_serv(acptr)->nn_capacity));
    send_reply(sptr, RPL_DATASTR, outbuf);

    if(IsBurst(acptr))
        send_reply(sptr, RPL_DATASTR, "         Status: Bursting");
    if(IsBurstAck(acptr))
        send_reply(sptr, RPL_DATASTR, "         Status: Awaiting EOB Ack");
    if(IsService(acptr))
        send_reply(sptr, RPL_DATASTR, "         Status: Network Service");
    if(IsHub(acptr))
        send_reply(sptr, RPL_DATASTR, "         Status: Network Hub");
    else
        send_reply(sptr, RPL_DATASTR, "         Status: Network Leaf");

    send_reply(sptr, RPL_DATASTR, " ");
    send_reply(sptr, RPL_DATASTR, "Downlinks:");
    for(slink = cli_serv(acptr)->down; slink; slink = slink->next) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "[%d] - %s%s", ++dlinkc,
                      IsBurst(slink->value.cptr) ? "*" : IsBurstAck(slink->value.cptr) ? "!" :
                      IsService(slink->value.cptr) ? "=" :IsHub(slink->value.cptr) ? "+" : " ",
                      cli_name(slink->value.cptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
    }
    if(!dlinkc)
        send_reply(sptr, RPL_DATASTR, "<none>");

    /* Send 'END OF CHECK' message */
    send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkClient(struct Client *sptr, struct Client *acptr, int flags) {
    struct Channel *chptr;
    struct Membership *lp;
    char outbuf[BUFSIZE], *ptr;
    time_t nowr;

    /* Header */
    send_reply(sptr, RPL_CHKHEAD, "user", acptr->cli_name);
    send_reply(sptr, RPL_DATASTR, " ");

    ircd_snprintf(0, outbuf, sizeof(outbuf), "            Nick: %s (%s%s)", acptr->cli_name, NumNick(acptr));
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "       Signed on: %s", MyUser(acptr)?myctime(acptr->cli_firsttime):"<unknown>");
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "       Timestamp: %s (%d)", myctime(acptr->cli_lastnick), acptr->cli_lastnick);
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "           Ident: %s", acptr->cli_user->username);
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "Current Hostmask: %s", acptr->cli_user->host);
    send_reply(sptr, RPL_DATASTR, outbuf);

    ircd_snprintf(0, outbuf, sizeof(outbuf), "       Real Host: %s (%s)", acptr->cli_user->realhost, ircd_ntoa(&(cli_ip(acptr))));
    send_reply(sptr, RPL_DATASTR, outbuf);

    if(IsAccount(acptr)) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "         Account: %s (%s)", acptr->cli_user->account, acptr->cli_user->acc_create?myctime(acptr->cli_user->acc_create):"0");
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    if(IsFakeHost(acptr)) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "       Fake Host: %s%c", acptr->cli_user->fakehost, COLOR_OFF);
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    ircd_snprintf(0, outbuf, sizeof(outbuf), "       Real Name: %s%c", cli_info(acptr), COLOR_OFF);
    send_reply(sptr, RPL_DATASTR, outbuf);

    if(IsAnOper(acptr))
        send_reply(sptr, RPL_DATASTR, "          Status: IRC Operator");

    ircd_snprintf(0, outbuf, sizeof(outbuf), "    Connected to: %s", cli_name(acptr->cli_user->server));
    send_reply(sptr, RPL_DATASTR, outbuf);

    ptr = umode_str(acptr);
    if(strlen(ptr) < 1)
        strcpy(outbuf, "        Umode(s): <none>");
    else
        ircd_snprintf(0, outbuf, sizeof(outbuf), "        Umode(s): +%s", ptr);
    send_reply(sptr, RPL_DATASTR, outbuf);

    if(acptr->cli_user->joined == 0)
        send_reply(sptr, RPL_DATASTR, "      Channel(s): <none>");
    else if(!(flags & CHECK_CHECKCHAN) && acptr->cli_user->joined > 50) {
        /* NB. As a sanity check, we DO NOT show the individual channels the
         *     client is on if it is on > 50 channels.  This is to prevent the ircd
         *     barfing ala Uworld when someone does /quote check Q :).. (I shouldn't imagine
         *     an Oper would want to see every single channel 'x' client is on anyway if
         *     they are on *that* many).
         */
        ircd_snprintf(0, outbuf, sizeof(outbuf), "      Channel(s): - (total: %u)", acptr->cli_user->joined);
        send_reply(sptr, RPL_DATASTR, outbuf);
    }
    else {
        char chntext[BUFSIZE];
        int len = strlen("      Channel(s): ");
        int mlen = strlen(me.cli_name) + len + strlen(sptr->cli_name);
        *chntext = '\0';

        strcpy(chntext, "      Channel(s): ");
        for(lp = acptr->cli_user->channel; lp; lp = lp->next_channel) {
            chptr = lp->channel;
            if(len + strlen(chptr->chname) + mlen > BUFSIZE - 5) {
                send_reply(sptr, RPL_DATASTR, chntext);
                *chntext = '\0';
                strcpy(chntext, "      Channel(s): ");
                len = strlen(chntext);
            }
            if(IsDeaf(acptr))
                *(chntext + len++) = '-';
            if(is_chan_op(acptr, chptr))
                *(chntext + len++) = '@';
            else if(has_voice(acptr, chptr))
                *(chntext + len++) = '+';
            else if(IsZombie(lp))
                *(chntext + len++) = '!';
            if(len)
                *(chntext + len) = '\0';

            strcpy(chntext + len, chptr->chname);
            len += strlen(chptr->chname);
            strcat(chntext + len, " ");
            len++;
        }

        if(chntext[0] != '\0')
            send_reply(sptr, RPL_DATASTR, chntext);
    }

    /* If client processing command ISN'T target (or a registered
     * Network Service), show idle time since the last time we
     * parsed something.
     */
    if(MyUser(acptr)) {
        nowr = CurrentTime - acptr->cli_user->last;
        ircd_snprintf(0, outbuf, sizeof(outbuf), "        Idle for: %d days, %02ld:%02ld:%02ld",
            nowr / 86400, (nowr / 3600) % 24, (nowr / 60) % 60, nowr % 60);
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    /* Away message (if applicable) */
    if(acptr->cli_user->away) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "    Away message: %s", acptr->cli_user->away);
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    /* If local user.. */
    if(MyUser(acptr)) {
        send_reply(sptr, RPL_DATASTR, " ");
        ircd_snprintf(0, outbuf, sizeof(outbuf), "            Port: %d", cli_listener(acptr)->addr.port);
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "       Data sent: %0.3u bytes", cli_receiveB(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "   Data received: %0.3u bytes", cli_sendB(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "   receiveQ size: %d bytes (max. %d bytes)", DBufLength(&(cli_recvQ(acptr))), feature_int(FEAT_CLIENT_FLOOD));
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(0, outbuf, sizeof(outbuf), "      sendQ size: %d bytes (max. %d bytes)", DBufLength(&(cli_sendQ(acptr))), get_sendq(acptr));
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    send_reply(sptr, RPL_ENDOFCHECK, " ");
}

void checkChannel(struct Client *sptr, struct Channel *chptr) {
    char outbuf[TOPICLEN + MODEBUFLEN + 64], modebuf[MODEBUFLEN], parabuf[MODEBUFLEN];

    /* Header */
    send_reply(sptr, RPL_CHKHEAD, "channel", chptr->chname);
    send_reply(sptr, RPL_DATASTR, " ");

    /* Creation Time */
    ircd_snprintf(sptr, outbuf, sizeof(outbuf), "  Creation time: %s", myctime(chptr->creationtime));
    send_reply(sptr, RPL_DATASTR, outbuf);

    /* Topic */
    if(strlen(chptr->topic) <= 0)
        send_reply(sptr, RPL_DATASTR, "          Topic: <none>");
    else {
        ircd_snprintf(sptr, outbuf, sizeof(outbuf), "          Topic: %s", chptr->topic);
        send_reply(sptr, RPL_DATASTR, outbuf);
        ircd_snprintf(sptr, outbuf, sizeof(outbuf), "         Set by: %s", chptr->topic_nick);
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    strcpy(outbuf, "Channel mode(s): ");

    modebuf[0] = '\0';
    parabuf[0] = '\0';
    channel_modes(sptr, modebuf, parabuf, sizeof(modebuf), chptr, 0);

    if(modebuf[1] == '\0')
        strcat(outbuf, "<none>");
    else if(*parabuf) {
        strcat(outbuf, modebuf);
        strcat(outbuf, " ");
        strcat(outbuf, parabuf);
    }
    else
        strcat(outbuf, modebuf);

    send_reply(sptr, RPL_DATASTR, outbuf);
    /* Don't send 'END OF CHECK' message, it's sent in checkUsers, which is called after this. */
}

void checkUsers(struct Client *sptr, struct Channel *chptr, int flags) {
    struct Membership *lp;
    struct Ban *channelban;
    struct Client *acptr;

    char outbuf[BUFSIZE], ustat[64];
    int cntr = 0, opcntr = 0, vcntr = 0, clones = 0, bans = 0, c = 0, authed = 0;

    if(flags & CHECK_SHOWUSERS) send_reply(sptr, RPL_DATASTR, "Users (@ = op, + = voice)");

    for(lp = chptr->members; lp; lp = lp->next_member) {
        int opped = 0;

        acptr = lp->user;
        if((c = checkClones(chptr, acptr->cli_name, acptr->cli_user->realhost)) != 0) {
            ircd_snprintf(0, ustat, sizeof(ustat), "%2d ", c);
            clones++;
        }
        else
            strcpy(ustat, "   ");

        if(chptr && is_chan_op(acptr, chptr)) {
            strcat(ustat, "@");
            opcntr++;
            opped = 1;
        }
        else if(chptr && has_voice(acptr, chptr)) {
            strcat(ustat, "+");
            vcntr++;
        }
        else
            strcat(ustat, " ");

        if((c = IsAccount(acptr)) != 0) ++authed;
        if((flags & CHECK_SHOWUSERS) && (!(flags & CHECK_OPSONLY) || opped)) {
            ircd_snprintf(0, outbuf, sizeof(outbuf), "%s%c", acptr->cli_info, COLOR_OFF);
            send_reply(sptr, RPL_CHANUSER, ustat, acptr->cli_name, acptr->cli_user->username,
                       (flags & CHECK_SHOWIPS) ? ircd_ntoa(&cli_ip(acptr)) : acptr->cli_user->realhost, outbuf, 
                       (c ? acptr->cli_user->account : ""));
        }

        cntr++;
    }

    ircd_snprintf(0, outbuf, sizeof(outbuf), "Total users: %d (%d ops, %d voiced, %d clones, %d authed)",
                  cntr, opcntr, vcntr, clones, authed);
    send_reply(sptr, RPL_DATASTR, outbuf);

    /* Do not display bans if ! flags & CHECK_SHOWUSERS */
    if(!(flags & CHECK_SHOWUSERS)) {
        send_reply(sptr, RPL_ENDOFCHECK, " ");
        return;
    }

    send_reply(sptr, RPL_DATASTR, " ");
    /* Bans */
    send_reply(sptr, RPL_DATASTR, "Bans/Exceptions on channel:");

    for(channelban = chptr->banlist; channelban; channelban = channelban->next) {
        ircd_snprintf(0, outbuf, sizeof(outbuf),  "%c [%d] - %s - Set by %s, on %s", (channelban->flags & BAN_EXCEPTION)?'e':'b',
                      ++bans, channelban->banstr, channelban->who, myctime(channelban->when));
        send_reply(sptr, RPL_DATASTR, outbuf);
    }

    if(bans == 0)
        send_reply(sptr, RPL_DATASTR, "<none>");

    send_reply(sptr, RPL_ENDOFCHECK, " ");
}

