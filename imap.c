/* Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       imap.c
  project:      fetchmail
  programmer:   Eric S. Raymond
  description:  IMAP client code

Chris Newman, one of the IMAP maintainers, criticized this as follows:
------------------------------- CUT HERE -----------------------------------
On Wed, 18 Sep 1996, Eric S. Raymond wrote:
> 1. I do one one SELECT, at the beginning of the fetch.  
> 
> 2. I assume that I can pick an upper bound on message numbers from the EXISTS
>    reponse.

Correct.

> 3. If there is an UNSEEN nnn trailer on the OK response to SELECT, I assume
>    that the unseen messages have message numbers which are the nnn consecutive
>    integers up to and including the upper bound.
> 
> 4. Otherwise, if the response included RECENT nnn, I assume that the unseen
>    messages have message numbers which are the nnn consecutive integers up to
>    and including the upper bound.

These will only work if your client is the only client that accesses the
INBOX.  There is no requirement that the UNSEEN and RECENT messages are at
the end of the folder in general.

If you want to present all UNSEEN messages and flag all the messages you
download as SEEN, you could do a SEARCH UNSEEN and just fetch those
messages.

However, the proper thing to do if you want to present the messages when
disconnected from the server is to use UIDs.  To do this, you remember the
highest UID you have (you can initialize to 0), and fetch everything with
a higher UID.  Ideally, you shouldn't cause the SEEN flag to be set until
the user has actually seen the message.  This requires STORE +FLAGS SEEN
for those messages which have been seen since the last update.

The key thing to remember is that in IMAP the server holds the
authoratative list of messages and the client just holds a cache.  This is
a very different model from POP.
------------------------------- CUT HERE -----------------------------------

A problem with this recommendation is that the UID commands don't exist
in IMAP2bis.  Since we want to preserve IMAP2bis capability (so fetchmail
will continue to work with the pre-IMAP4 imapd) and we've warned the user
that multiple concurrent fetchmail runs are a Bad Idea, we'll stick with
this logic for now.

 ***********************************************************************/

#include  <config.h>
#include  <stdio.h>
#include  "socket.h"
#include  "fetchmail.h"

/*********************************************************************

 Method declarations for IMAP 

 *********************************************************************/

static int count, first;
static int exists, unseen, recent;

int imap_ok (argbuf,socket)
/* parse command response */
char *argbuf;
int socket;
{
  int ok;
  char buf [POPBUFSIZE+1];
  char *bufp;
  int n;

  do {
    if (SockGets(socket, buf, sizeof(buf)) < 0)
      return(PS_SOCKET);

    if (outlevel == O_VERBOSE)
      fprintf(stderr,"%s\n",buf);

    /* interpret untagged status responses */
    if (strstr(buf, "EXISTS"))
	exists = atoi(buf+2);
    if (strstr(buf, "RECENT"))
	recent = atoi(buf+2);
    if (sscanf(buf + 2, "OK [UNSEEN %d]", &n) == 1)
	unseen = n;

  } while
      (tag[0] != '\0' && strncmp(buf, tag, strlen(tag)));

  if (tag[0] == '\0') {
    strcpy(argbuf, buf);
    return(0); 
  }
  else {
    if (strncmp(buf + TAGLEN + 1, "OK", 2) == 0) {
      strcpy(argbuf, buf + TAGLEN);
      return(0);
    }
    else if (strncmp(buf + TAGLEN + 1, "BAD", 2) == 0)
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
		  "LOGIN %s %s",
		  queryctl->remotename, queryctl->password));
}

static imap_getrange(socket, queryctl, countp, firstp)
/* get range of messages to be fetched */
int socket;
struct hostrec *queryctl;
int *countp;
int *firstp;
{
    int ok;

    /* find out how many messages are waiting */
    exists = unseen = recent = -1;
    ok = gen_transact(socket,
		  "SELECT %s",
		  queryctl->remotefolder[0] ? queryctl->remotefolder : "INBOX");
    if (ok != 0)
	return(ok);

    /* compute size of message run */
    *countp = exists;
    if (queryctl->fetchall)
	*firstp = 1;
    else {
	if (exists > 0 && unseen == -1) {
	    fprintf(stderr,
		    "no UNSEEN response; assuming all %d RECENT messages are unseen\n",
		    recent);
	    *firstp = exists - recent + 1;
	} else {
	    *firstp = unseen;
	}
    }

    return(0);
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
    return(socket, gen_transact("STORE %d +FLAGS (\\Deleted)", number));
}

static struct method imap =
{
    "IMAP",		/* Internet Message Access Protocol */
    143,		/* standard IMAP2bis/IMAP4 port */
    1,			/* this is a tagged protocol */
    0,			/* no message delimiter */
    imap_ok,		/* parse command response */
    imap_getauth,	/* get authorization */
    imap_getrange,	/* query range of messages */
    NULL,		/* no UID check */
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


