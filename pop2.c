/*
 * pop2.c -- POP@ protocol methods
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#include  "socket.h"
#include  "fetchmail.h"

static int pound_arg, equal_arg;

int pop2_ok (socket, argbuf)
/* parse POP2 command response */
int socket;
char *argbuf;
{
    int ok;
    char buf [POPBUFSIZE+1];

    pound_arg = equal_arg = -1;
    if (SockGets(socket, buf, sizeof(buf)) >= 0) {
	if (outlevel == O_VERBOSE)
	    fprintf(stderr,"%s\n",buf);

	if (buf[0] == '+')
	    ok = 0;
	else if (buf[0] == '#')
	{
	    pound_arg = atoi(buf+1);
	    ok = 0;
	}
	else if (buf[0] == '=')
	{
	    equal_arg = atoi(buf+1);
	    ok = 0;
	}
	else if (buf[0] == '-')
	    ok = PS_ERROR;
	else
	    ok = PS_PROTOCOL;

	if (argbuf != NULL)
	    strcpy(argbuf,buf);
    }
    else 
	ok = PS_SOCKET;

    return(ok);
}

int pop2_getauth(socket, ctl, buf)
/* apply for connection authorization */
int socket;
struct query *ctl;
char *buf;
{
    return(gen_transact(socket,
		  "HELO %s %s",
		  ctl->remotename, ctl->password));
}

static int pop2_getrange(socket, ctl, countp, newp)
/* get range of messages to be fetched */
int socket;
struct query *ctl;
int *countp, *newp;
{
    /*
     * We should have picked up a count of messages in the user's
     * default inbox from the pop2_getauth() response.
     */
    if (pound_arg == -1)
	return(PS_ERROR);

    /* maybe the user wanted a non-default folder */
    if (ctl->mailbox[0])
    {
	int	ok = gen_transact(socket, "FOLD %s", ctl->mailbox);

	if (ok != 0)
	    return(ok);
	if (pound_arg == -1)
	    return(PS_ERROR);
    }

    *countp = pound_arg;
    *newp = -1;

    return(0);
}

static int pop2_fetch(socket, number, lenp)
/* request nth message */
int socket;
int number;
int *lenp; 
{
    int	ok;

    *lenp = 0;
    ok = gen_transact(socket, "READ %d", number);
    if (ok)
	return(0);
    *lenp = equal_arg;

    gen_send(socket, "RETR");

    return(ok);
}

static int pop2_trail(socket, ctl, number)
/* send acknowledgement for message data */
int socket;
struct query *ctl;
int number;
{
    return(gen_transact(socket, ctl->keep ? "ACKS" : "ACKD"));
}

const static struct method pop2 =
{
    "POP2",				/* Post Office Protocol v2 */
    109,				/* standard POP2 port */
    0,					/* this is not a tagged protocol */
    0,					/* does not use message delimiter */
    pop2_ok,				/* parse command response */
    pop2_getauth,			/* get authorization */
    pop2_getrange,			/* query range of messages */
    NULL,				/* no way to get sizes */
    NULL,				/* messages are always new */
    pop2_fetch,				/* request given message */
    pop2_trail,				/* eat message trailer */
    NULL,				/* no POP2 delete method */
    NULL,				/* no POP2 expunge command */
    "QUIT",				/* the POP2 exit command */
};

int doPOP2 (ctl)
/* retrieve messages using POP2 */
struct query *ctl;
{
    return(do_protocol(ctl, &pop2));
}

/* pop2.c ends here */
