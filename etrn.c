/*
 * etrn.c -- ETRN protocol methods
 *
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#include  "fetchmail.h"
#include  "smtp.h"
#include  "socket.h"

static int etrn_ok (FILE *sockfp, char *argbuf)
/* parse command response */
{
    int ok;
    char buf [POPBUFSIZE+1];

    ok = SMTP_ok(sockfp);
    if (ok == SM_UNRECOVERABLE)
	return(PS_PROTOCOL);
    else
	return(ok);
}

static int etrn_getrange(FILE *sockfp, struct query *ctl, int*countp, int*newp)
/* send ETRN and interpret the response */
{
    int ok, opts;
    char buf [POPBUFSIZE+1];

    if ((ok = SMTP_ehlo(sockfp, ctl->server.names->id, &opts)))
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

    /* ship the actual poll and get the response */
    gethostbyname(buf, sizeof(buf));
    gen_send(sockfp, "ETRN %s", buf);
    if (ok = gen_recv(sockfp, buf, sizeof(buf)))
	return(ok);

    /* this switch includes all the response codes described in RFC1985 */
    switch(atoi(buf))
    {
    case 250:	/* OK, queuing for node <x> started */
	error(0, 0, "Queuing for %s started", ctl->server.names->id);
	break;

    case 251:	/* OK, no messages waiting for node <x> */
	error(0, 0, "No messages waiting for %s", ctl->server.names->id);
	return(PS_NOMAIL);

    case 252:	/* OK, pending messages for node <x> started */
    case 253:	/* OK, <n> pending messages for node <x> started */
	error(0, 0, "Pending messages for %s started");
	break;

    case 458:	/* Unable to queue messages for node <x> */
	error(0, 0, "Unable to queue messages for node %s",
	      ctl->server.names->id);
	return(PS_PROTOCOL);

    case 459:	/* Node <x> not allowed: <reason> */
	error(0, 0, "Node %s not allowed: %s", ctl->server.names->id, buf);
	return(PS_AUTHFAIL);

    case 500:	/* Syntax Error */
	error(0, 0, "ETRN syntax error");
	return(PS_PROTOCOL);

    case 501:	/* Syntax Error in Parameters */
	error(0, 0, "ETRN syntax error in parameters");
	return(PS_PROTOCOL);

    default:
	error(0, 0, "Unknown ETRN error");
	return(PS_PROTOCOL);
    }

    return(0);
}

const static struct method etrn =
{
    "ETRN",		/* ESMTP ETRN extension */
    25,			/* standard SMTP port */
    FALSE,		/* this is not a tagged protocol */
    FALSE,		/* this does not use a message delimiter */
    etrn_ok,		/* parse command response */
    NULL,		/* no need to get authentication */
    etrn_getrange,	/* initialize message sending */
    NULL,		/* we cannot get a list of sizes */
    NULL,		/* how do we tell a message is old? */
    NULL,		/* request given message */
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
    if (ctl->mailbox) {
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
