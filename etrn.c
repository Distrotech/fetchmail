/*
 * etrn.c -- ETRN protocol methods
 *
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"
#include  <stdio.h>
#include  <stdlib.h>
#include  <assert.h>
#include  <netdb.h>
#include  <errno.h>
#include  "fetchmail.h"
#include  "smtp.h"
#include  "socket.h"

static int etrn_ok (int sock, char *argbuf)
/* parse command response */
{
    int ok;

    ok = SMTP_ok(sock);
    if (ok == SM_UNRECOVERABLE)
	return(PS_PROTOCOL);
    else
	return(ok);
}

static int etrn_getrange(int sock, struct query *ctl, char *id, int *countp,
                                                                    int *newp)
/* send ETRN and interpret the response */
{
    int ok, opts, qdone = 0;
    char buf [POPBUFSIZE+1],
	 hname[256];
    const char *qname;
    struct idlist *qnp;		/* pointer to Q names */
    struct hostent *hp;

    if ((ok = SMTP_ehlo(sock, ctl->server.names->id, &opts)))
    {
	error(0, 0, "%s's SMTP listener does not support ESMTP",
	      ctl->server.names->id);
	return(ok);
    }
    else if (!(opts & ESMTP_ETRN))
    {
	error(0, 0, "%s's SMTP listener does not support ETRN",
	      ctl->server.names->id);
	return(PS_PROTOCOL);
    }

    *countp = *newp = -1;	/* make sure we don't enter the fetch loop */

    /*** This is a sort of horrible HACK because the ETRN protocol
     *** does not fit very well into the mailbox concept used in
     *** this program (IMHO).  The last element of ctl->smtphunt
     *** turned out to be the host being queried (i.e., the smtp server).
     *** for that reason the rather "funny" condition in the for loop.
     *** Isn't it sort of unreasonable to add the server to the ETRN
     *** hunt list? (Concerning ETRN I'm sure! In case I want a Q-run of
     *** my SMTP-server I can always specify -Smyserver, and this is only
     *** resonable if I start sendmail without -qtime and in Q-only mode.)
     *** 
     *** -- 1997-06-22 Guenther Leber
     ***/
    /* do it for all queues in the smtphunt list except the last one
       which is the SMTP-server itself */
    for (qnp = ctl->smtphunt; ( (qnp != (struct idlist *) NULL) && 
		(qnp->next != (struct idlist *) NULL) ) || (qdone == 0);
		qnp = qnp->next, qdone++)
    {

	/* extract name of Q */
        if ( (qnp != (struct idlist *) NULL) &&
				(qnp->next != (struct idlist *) NULL) )
	{
	    /* take Q-name given in smtp hunt list */
	    qname = qnp->id;
	} else {
	    assert(qdone == 0);
	    /*** use fully qualified host name as Q name ***/
	    /* get hostname */
	    if (gethostname(hname, sizeof hname) != 0)
	    {
		/* exit with error message */
	        error(5, errno, "gethostname");
	    }
	    /* in case we got a host basename (as we do in Linux),
	       make a FQDN of it				*/
	    hp = gethostbyname(hname);
	    if (hp == (struct hostent *) NULL)
	    {
		/* exit with error message */
	        error(5, h_errno, "gethostbyname");
	    }
	    /* here it is */
	    qname = hp->h_name;
	}


        /* ship the actual poll and get the response */
        gen_send(sock, "ETRN %s", qname);
        if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);

        /* this switch includes all the response codes described in RFC1985 */
        switch(atoi(buf))
        {
        case 250:	/* OK, queuing for node <x> started */
	    error(0, 0, "Queuing for %s started", qname);
	    break;

        case 251:	/* OK, no messages waiting for node <x> */
	    error(0, 0, "No messages waiting for %s", qname);
	    return(PS_NOMAIL);

        case 252:	/* OK, pending messages for node <x> started */
        case 253:	/* OK, <n> pending messages for node <x> started */
	    error(0, 0, "Pending messages for %s started", qname);
	    break;

        case 458:	/* Unable to queue messages for node <x> */
	    error(0, -1, "Unable to queue messages for node %s", qname);
	    return(PS_PROTOCOL);

        case 459:	/* Node <x> not allowed: <reason> */
	    error(0, -1, "Node %s not allowed: %s", qname, buf);
	    return(PS_AUTHFAIL);

        case 500:	/* Syntax Error */
	    error(0, -1, "ETRN syntax error");
	    return(PS_PROTOCOL);

        case 501:	/* Syntax Error in Parameters */
	    error(0, -1, "ETRN syntax error in parameters");
	    return(PS_PROTOCOL);

        default:
	    error(0, -1, "Unknown ETRN error %d", atoi(buf));
	    return(PS_PROTOCOL);
        }
    }

    return(0);
}

const static struct method etrn =
{
    "ETRN",		/* ESMTP ETRN extension */
    25,			/* standard SMTP port */
    FALSE,		/* this is not a tagged protocol */
    FALSE,		/* this does not use a message delimiter */
    FALSE,		/* no getsizes method */
    etrn_ok,		/* parse command response */
    NULL,		/* no need to get authentication */
    etrn_getrange,	/* initialize message sending */
    NULL,		/* we cannot get a list of sizes */
    NULL,		/* how do we tell a message is old? */
    NULL,		/* no way to fetch headers */
    NULL,		/* no way to fetch body */
    NULL,		/* no message trailer */
    NULL,		/* how to delete a message */
    "QUIT",		/* the ETRN exit command */
};

int doETRN (struct query *ctl)
/* retrieve messages using ETRN */
{
    if (ctl->keep) {
	fprintf(stderr, "Option --keep is not supported with ETRN\n");
	return(PS_SYNTAX);
    }
    if (ctl->flush) {
	fprintf(stderr, "Option --flush is not supported with ETRN\n");
	return(PS_SYNTAX);
    }
    if (ctl->mailboxes->id) {
	fprintf(stderr, "Option --remote is not supported with ETRN\n");
	return(PS_SYNTAX);
    }
    if (check_only) {
	fprintf(stderr, "Option --check is not supported with ETRN\n");
	return(PS_SYNTAX);
    }
    peek_capable = FALSE;
    return(do_protocol(ctl, &etrn));
}

/* etrn.c ends here */
