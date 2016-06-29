/*
 * IRC - Internet Relay Chat, ircd/m_svsmode.c
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

/** SVSMODE
 * SVSMODE is forwarded to the users server, hence, it can be called
 * from any server.
 */
/* ms_svsmode - server message handler
 * parv[0] = sender prefix
 * parv[1] = target numeric
 * parv[2-X] = mode string
 */
signed int ms_svsmode(struct Client* cptr, struct Client* sptr, signed int parc, char* parv[]) {
    struct Client *acptr;
    unsigned int i;
    char buffer[512];
    char *act, *m;
    struct Flags setflags;

    if(parc < 3) {
        return protocol_violation(cptr, "Too few arguments for SVSMODE");
    }

    if(!(acptr = findNUser(parv[1]))) {
        return 0; /* Ignore SVSMODE for a user that has quit */
    }

    /* Forward the message to the server where the user is connected to. */
    if(!MyConnect(acptr)) {
        act = buffer;
        for(i = 2; i < (parc - 1); ++i) {
            m = parv[i];
            while((*act++ = *m++)) /* empty loop */ ;
            *(act - 1) = ' ';
        }
        m = parv[i];
        *act++ = ':';
        while((*act++ = *m++)) /* empty loop */ ;
        sendcmdto_one(sptr, CMD_SVSMODE, acptr, "%s %s", parv[1], buffer);
        return 0;
    }

    /* Set mode change. */
    setflags = cli_flags(acptr);
    set_user_mode(&me, acptr, parc, parv, ALLOWMODES_ANY);
    send_umode(acptr, acptr, &setflags, ALL_UMODES, 0);
    return 0;
}

