/*
 * imap.c -- IMAP2bis/IMAP4 protocol methods
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#include  <string.h>
#include  <ctype.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#include  "fetchmail.h"
#include  "socket.h"

static int count, seen, recent, unseen, imap4;

int imap_ok (FILE *sockfp,  char *argbuf)
/* parse command response */
{
    char buf [POPBUFSIZE+1];

    seen = 0;
    do {
	if (!SockGets(buf, sizeof(buf), sockfp))
	    return(PS_SOCKET);
	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\r';

	if (outlevel == O_VERBOSE)
	    error(0, 0, "IMAP< %s", buf);

	/* interpret untagged status responses */
	if (strstr(buf, "EXISTS"))
	    count = atoi(buf+2);
	if (strstr(buf, "RECENT"))
	    recent = atoi(buf+2);
	if (strstr(buf, "UNSEEN"))
	    unseen = atoi(buf+2);
	if (strstr(buf, "FLAGS"))
	    seen = (strstr(buf, "Seen") != (char *)NULL);
    } while
	(tag[0] != '\0' && strncmp(buf, tag, strlen(tag)));

    if (tag[0] == '\0')
    {
	strcpy(argbuf, buf);
	return(0); 
    }
    else
    {
	char	*cp;

	/* skip the tag */
	for (cp = buf; !isspace(*cp); cp++)
	    continue;
	while (isspace(*cp))
	    cp++;

	if (strncmp(cp, "OK", 2) == 0)
	{
	    strcpy(argbuf, cp);
	    return(0);
	}
	else if (strncmp(cp, "BAD", 2) == 0)
	    return(PS_ERROR);
	else
	    return(PS_PROTOCOL);
    }
}

int imap_getauth(FILE *sockfp, struct query *ctl, char *buf)
/* apply for connection authorization */
{
    /* try to get authorized */
    int ok = gen_transact(sockfp,
		  "LOGIN %s \"%s\"",
		  ctl->remotename, ctl->password);

    if (ok)
	return(ok);

    /* probe to see if we're running IMAP4 and can use RFC822.PEEK */
    imap4 = ((gen_transact(sockfp, "CAPABILITY")) == 0);

    return(0);
}

static int imap_getrange(FILE *sockfp, struct query *ctl, int*countp, int*newp)
/* get range of messages to be fetched */
{
    int ok;

    /* find out how many messages are waiting */
    recent = unseen = 0;
    ok = gen_transact(sockfp,
		  "SELECT %s",
		  ctl->mailbox ? ctl->mailbox : "INBOX");
    if (ok != 0)
	return(ok);

    *countp = count;

    if (unseen)		/* optional response, but better if we see it */
	*newp = unseen;
    else if (recent)	/* mandatory */
	*newp = recent;
    else
	*newp = -1;	/* should never happen, RECENT is mandatory */ 

    return(0);
}

static int imap_getsizes(FILE *sockfp, int count, int *sizes)
/* capture the sizes of all messages */
{
    char buf [POPBUFSIZE+1];

    gen_send(sockfp, "FETCH 1:%d RFC822.SIZE", count);
    while (SockGets(buf, sizeof(buf), sockfp))
    {
	int num, size;

	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\r';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "IMAP< %s", buf);
	if (strstr(buf, "OK"))
	    break;
	else if (sscanf(buf, "* %d FETCH (RFC822.SIZE %d)", &num, &size) == 2)
	    sizes[num - 1] = size;
	else
	    sizes[num - 1] = -1;
    }

    return(0);
}

static int imap_is_old(FILE *sockfp, struct query *ctl, int num)
/* is the given message old? */
{
    int ok;

    if ((ok = gen_transact(sockfp, "FETCH %d FLAGS", num)) != 0)
	return(PS_ERROR);

    return(seen);
}

static int imap_fetch(FILE *sockfp, struct query *ctl, int number, int *lenp)
/* request nth message */
{
    char buf [POPBUFSIZE+1];
    int	num;

    /*
     * If we're using IMAP4, we can fetch the message without setting its
     * seen flag.  This is good!  It means that if the protocol exchange
     * craps out during the message, it will still be marked `unseen' on
     * the server.
     *
     * However...*don't* do this if we're using keep to suppress deletion!
     * In that case, marking the seen flag is the only way to prevent the
     * message from being re-fetched on subsequent runs.
     */
    if (imap4 && !ctl->keep)
	gen_send(sockfp, "FETCH %d RFC822.PEEK", number);
    else
	gen_send(sockfp, "FETCH %d RFC822", number);

    /* looking for FETCH response */
    do {
	if (!SockGets(buf, sizeof(buf), sockfp))
	    return(PS_SOCKET);
    } while
	    (sscanf(buf+2, "%d FETCH (RFC822 {%d}", &num, lenp) != 2);

    if (num != number)
	return(PS_ERROR);
    else
	return(0);
}

static int imap_trail(FILE *sockfp, struct query *ctl, int number)
/* discard tail of FETCH response after reading message text */
{
    char buf [POPBUFSIZE+1];

    if (!SockGets(buf, sizeof(buf), sockfp))
	return(PS_SOCKET);
    else
	return(0);
}

static int imap_delete(FILE *sockfp, struct query *ctl, int number)
/* set delete flag for given message */
{
    int	ok;

    /* use SILENT if possible as a minor throughput optimization */
    if ((ok = gen_transact(sockfp,
			imap4 
				? "STORE %d +FLAGS.SILENT (\\Deleted)"
				: "STORE %d +FLAGS (\\Deleted)", 
			number)))
	return(ok);

    return(gen_transact(sockfp, "EXPUNGE"));
}

const static struct method imap =
{
    "IMAP",		/* Internet Message Access Protocol */
    143,		/* standard IMAP2bis/IMAP4 port */
    1,			/* this is a tagged protocol */
    0,			/* no message delimiter */
    imap_ok,		/* parse command response */
    imap_getauth,	/* get authorization */
    imap_getrange,	/* query range of messages */
    imap_getsizes,	/* grab message sizes */
    imap_is_old,	/* no UID check */
    imap_fetch,		/* request given message */
    imap_trail,		/* eat message trailer */
    imap_delete,	/* set IMAP delete flag */
    "LOGOUT",		/* the IMAP exit command */
};

int doIMAP(struct query *ctl)
/* retrieve messages using IMAP Version 2bis or Version 4 */
{
    return(do_protocol(ctl, &imap));
}

/* imap.c ends here */
