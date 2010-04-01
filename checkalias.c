/*
 * checkalias.c -- check to see if two hostnames or IP addresses are equivalent
 *
 * Copyright 1997 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "fetchmail.h"

int is_host_alias(const char *name, struct query *ctl, struct addrinfo **res)
/* determine whether name is a DNS alias of the mailserver for this query */
{
    struct idlist	*idl;
    size_t		namelen;

    struct hostdata *lead_server =
	ctl->server.lead_server ? ctl->server.lead_server : &ctl->server;

    /*
     * The first two checks are optimizations that will catch a good
     * many cases.
     *
     * (1) check against the `true name' deduced from the poll label
     * and the via option (if present) at the beginning of the poll cycle.
     * Odds are good this will either be the mailserver's FQDN or a suffix of
     * it with the mailserver's domain's default host name omitted.
     *
     * (2) Then check the rest of the `also known as'
     * cache accumulated by previous DNS checks.  This cache is primed
     * by the aka list option.
     *
     * Any of these on a mail address is definitive.  Only if the
     * name doesn't match any is it time to call the bind library.
     * If this happens odds are good we're looking at an MX name.
     */
    if (strcasecmp(lead_server->truename, name) == 0)
	return(TRUE);
    else if (str_in_list(&lead_server->akalist, name, TRUE))
	return(TRUE);

    /*
     * Now check for a suffix match on the akalist.  The theory here is
     * that if the user says `aka netaxs.com', we actually want to match
     * foo.netaxs.com and bar.netaxs.com.
     */
    namelen = strlen(name);
    for (idl = lead_server->akalist; idl; idl = idl->next)
    {
	const char	*ep;

	/*
	 * Test is >= here because str_in_list() should have caught the
	 * equal-length case above.  Doing it this way guarantees that
	 * ep[-1] is a valid reference.
	 */
	if (strlen(idl->id) >= namelen)
	    continue;
	ep = name + (namelen - strlen(idl->id));
	/* a suffix led by . must match */
	if (ep[-1] == '.' && !strcasecmp(ep, idl->id))
	    return(TRUE);
    }

    if (!ctl->server.dns)
	return(FALSE);
    (void)res;
    return(FALSE);
}

/* checkalias.c ends here */
