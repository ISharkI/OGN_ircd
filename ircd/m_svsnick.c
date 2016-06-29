/*
 * IRC - Internet Relay Chat, ircd/m_svsnick.c
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

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

#include <stdlib.h>
#include <string.h>

/* Copied from m_nick.c.
 *
 * do_nick_name checks the nickname. WARNING: It MAY modify the nickname
 * RETURNS the length of the final NICKNAME (0, if nickname is invalid)
 *
 * Nickname characters are in range 'A'..'}', '_', '-', '0'..'9'
 *  anything outside the above set will terminate nickname.
 * In addition, the first character cannot be '-' or a Digit.
 */
static int do_nick_name(char* nick) {
    char *ch  = nick;
    char *end = ch + NICKLEN;
    assert(0 != ch);

    /* first character in [0..9-] */
    if(*ch == '-' || IsDigit(*ch)) return 0;
    for( ; (ch < end) && *ch; ++ch) {
        if(!IsNickChar(*ch)) break;
    }
    *ch = '\0';
    return (ch - nick);
}

/** SVSNICK
 * SVSNICK is forwarded to the users server, hence, it can be called
 * from any server.
 */
/* ms_svsnick - server message handler
 * parv[0] = sender prefix
 * parv[1] = target numeric
 * parv[2] = new nickname
 */
signed int ms_svsnick(struct Client* cptr, struct Client* sptr, signed int parc, char* parv[]) {
    struct Client *acptr = NULL;
    char nick[NICKLEN + 2];
    char *arg;
    char *s;

    if(parc < 3) {
        return protocol_violation(cptr, "Too few arguments for SVSNICK");
    }

    if(!(acptr = findNUser(parv[1]))) {
        return 0; /* Ignore SVSNICK for a user that has quit */
    }

    /* Limit the nicklen to NICKLEN. */
    arg = parv[2];
    if(strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))) {
        arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';
    }
    strcpy(nick, arg);

    if(!do_nick_name(nick)) {
        /* Invalid nickname. */
        return 0;
    }

    /* Check whether nickname is already set. */
    if(ircd_strcmp(cli_name(acptr), parv[2]) == 0) {
        return 0;
    }

    /* Check whether the nick is already used. */
    s = nick;
    if(FindClient(s)) {
        return 0;
    }

    /* Forward the message to the server where the user is connected to. */
    if(!MyConnect(acptr)) {
        sendcmdto_one(sptr, CMD_SVSNICK, acptr, "%s %s", parv[1], nick);
        return 0;
    }

    /* Set nickname. */
    set_nick_name(acptr, acptr, nick, parc, parv, 1);

    return 1;
}

/*
 * ms_svsnick_old - server message handler
 * parv[0] = sender prefix
 * parv[1] = Target numeric
 * parv[2] = New nickname
 */
int ms_svsnick_old(struct Client* cptr, struct Client* sptr, int parc, char* parv[]) {
    struct Client* acptr = NULL;
    char nick[NICKLEN + 2];
    char* arg;
    char* s;

    if(parc < 3)
        return(need_more_params(sptr, "SVSNICK"));

    if(!(acptr = findNUser(parv[1])))
        return 0; /* Ignore SVSNICK for a user that has quit */

    if(!find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD)) {
        return protocol_violation(cptr, "Non-U:lined server %s sets svsnick on user %s", cli_name(sptr), cli_name(acptr));
    }

    /*
     * Don't let them send make us send back a really long string of
     * garbage
     */
    arg = parv[2];
    if(strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
        arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

    if((s = strchr(arg, '~')))
        *s = '\0';

    strcpy(nick, arg);

    /*
     * If do_nick_name() returns a null name then reject it.
     */
    if(0 == do_nick_name(nick))
        return 0;

    if(ircd_strcmp(cli_name(acptr), nick) == 0)
        return 0; /* Nick already set to what SVSNICK wants, ignoring... */

    if(FindClient(nick))
        return 0; /* Target nick is in use */

    set_nick_name(acptr, acptr, nick, parc, parv, 1);
    sendcmdto_serv_butone(sptr, CMD_SVSNICK_OLD, cptr, "%s %s", parv[1], nick);
    return 0;
}

