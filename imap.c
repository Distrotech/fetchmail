/* Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       imap.c
  project:      fetchmail
  programmer:   Eric S. Raymond
  description:  IMAP client code

 ***********************************************************************/

#include  <config.h>
#include  <stdio.h>
#include  <string.h>
#include  "socket.h"
#include  "fetchmail.h"

/*********************************************************************

 Method declarations for IMAP 

 *********************************************************************/

static int count, seen;

int imap_ok (socket, argbuf)
/* parse command response */
char *argbuf;
int socket;
{
    int ok;
    char buf [POPBUFSIZE+1];
    char *bufp;
    int n;

    seen = 0;
    do {
	if (SockGets(socket, buf, sizeof(buf)) < 0)
	    return(PS_SOCKET);

	if (outlevel == O_VERBOSE)
	    fprintf(stderr,"%s\n",buf);

	/* interpret untagged status responses */
	if (strstr(buf, "EXISTS"))
	    count = atoi(buf+2);
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

int imap_getauth(socket, queryctl, buf)
/* apply for connection authorization */
int socket;
struct hostrec *queryctl;
char *buf;
{
    /* try to get authorized */
    return(gen_transact(socket,
		  "LOGIN %s \"%s\"",
		  queryctl->remotename, queryctl->password));
}

static imap_getrange(socket, queryctl, countp)
/* get range of messages to be fetched */
int socket;
struct hostrec *queryctl;
int *countp;
{
    int ok;

    /* find out how many messages are waiting */
    ok = gen_transact(socket,
		  "SELECT %s",
		  queryctl->mailbox[0] ? queryctl->mailbox : "INBOX");
    if (ok != 0)
	return(ok);

    *countp = count;

    return(0);
}

static imap_is_old(socket, queryctl, num)
int socket;
struct hostrec *queryctl;
int num;
{
    char buf [POPBUFSIZE+1];
    int ok;

    if ((ok = gen_transact(socket, "FETCH %d FLAGS", num)) != 0)
	exit(PS_ERROR);

    return(seen);
}

static int imap_fetch(socket, number, lenp)
/* request nth message */
int socket;
int number;
int *lenp; 
{
    char buf [POPBUFSIZE+1];
    int	num;

    gen_send(socket, "FETCH %d RFC822", number);

    /* looking for FETCH response */
    do {
	if (SockGets(socket, buf,sizeof(buf)) < 0)
	    return(PS_SOCKET);
    } while
	    (sscanf(buf+2, "%d FETCH (RFC822 {%d}", &num, lenp) != 2);

    if (num != number)
	return(PS_ERROR);
    else
	return(0);
}

static imap_trail(socket, queryctl, number)
/* discard tail of FETCH response */
int socket;
struct hostrec *queryctl;
int number;
{
    char buf [POPBUFSIZE+1];

    if (SockGets(socket, buf,sizeof(buf)) < 0)
	return(PS_SOCKET);
    else
	return(0);
}

static imap_delete(socket, queryctl, number)
/* set delete flag for given message */
int socket;
struct hostrec *queryctl;
int number;
{
    return(gen_transact(socket, "STORE %d +FLAGS.SILENT (\\Deleted)", number));
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
    imap_is_old,	/* no UID check */
    imap_fetch,		/* request given message */
    imap_trail,		/* eat message trailer */
    imap_delete,	/* set IMAP delete flag */
    "EXPUNGE",		/* the IMAP expunge command */
    "LOGOUT",		/* the IMAP exit command */
};

int doIMAP (queryctl)
/* retrieve messages using IMAP Version 2bis or Version 4 */
struct hostrec *queryctl;
{
    return(do_protocol(queryctl, &imap));
}


