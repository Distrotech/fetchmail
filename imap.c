/* Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       imap.c
  project:      popclient
  programmer:   Eric S. Raymond
  description:  IMAP client code

 ***********************************************************************/

#include  <config.h>
#include  <varargs.h>

#include  <stdio.h>
#if defined(STDC_HEADERS)
#include  <string.h>
#endif
#if defined(HAVE_UNISTD_H)
#include  <unistd.h>
#endif
#include  <errno.h>

#include  "socket.h"
#include  "popclient.h"

static int count, first;

/*********************************************************************

 Method declarations for IMAP 

 *********************************************************************/

static int exists, unseen, recent;

int imap_ok (argbuf,socket)
/* parse command response */
char *argbuf;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];
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

  if (tag[0] == '\0')
    return(0); 
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

static int imap_fetch(socket, number, limit, lenp)
/* request nth message */
int socket;
int number;
int limit;
int *lenp; 
{
    char buf [POPBUFSIZE];
    int	num;

    if (limit) 
	gen_send(socket,
		     "PARTIAL %d RFC822 0 %d",
		     number, limit);
    else 
	gen_send(socket,
		     "FETCH %d RFC822",
		     number);

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
    char buf [POPBUFSIZE];

    if (SockGets(socket, buf,sizeof(buf)) < 0)
	return(PS_SOCKET);
    else
	return(0);
}

static struct method imap =
{
    "IMAP",				/* Internet Message Access Protocol */
    143,				/* standard IMAP3bis/IMAP4 port */
    1,					/* this is a tagged protocol */
    0,					/* no message delimiter */
    imap_ok,				/* parse command response */
    imap_getauth,			/* get authorization */
    imap_getrange,			/* query range of messages */
    imap_fetch,				/* request given message */
    imap_trail,				/* eat message trailer */
    "STORE %d +FLAGS (\\Deleted)",	/* set IMAP delete flag */
    "EXPUNGE",				/* the IMAP expunge command */
    "LOGOUT",				/* the IMAP exit command */
};

int doIMAP (queryctl)
/* retrieve messages using IMAP Version 2bis or Version 4 */
struct hostrec *queryctl;
{
    return(do_protocol(queryctl, &imap));
}

