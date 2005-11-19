/*
 * pop2.c -- POP2 protocol methods
 *
 * Copyright 1997 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"

#ifdef POP2_ENABLE
#include  <stdio.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include  "fetchmail.h"
#include  "socket.h"

static int pound_arg, equal_arg;

static int pop2_ok (int sock, char *argbuf)
/* parse POP2 command response */
{
    int ok;
    char buf [POPBUFSIZE+1];

    pound_arg = equal_arg = -1;

    if ((ok = gen_recv(sock, buf, sizeof(buf))) == 0)
    {
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

    return(ok);
}

static int pop2_getauth(int sock, struct query *ctl, char *buf)
/* apply for connection authorization */
{
    int status;

    strlcpy(shroud, ctl->password, sizeof(shroud));
    status = gen_transact(sock,
		  "HELO %s %s",
		  ctl->remotename, ctl->password);
    shroud[0] = '\0';
    return status;
}

static int pop2_getrange(int sock, struct query *ctl, const char *folder, 
			 int *countp, int *newp, int *bytes)
/* get range of messages to be fetched */
{
    /* maybe the user wanted a non-default folder */
    if (folder)
    {
	int	ok = gen_transact(sock, "FOLD %s", folder);

	if (ok != 0)
	    return(ok);
	if (pound_arg == -1)
	    return(PS_ERROR);
    }
    else
	/*
	 * We should have picked up a count of messages in the user's
	 * default inbox from the pop2_getauth() response. 
	 *
	 * Note: this logic only works because there is no way to select
	 * both the unnamed folder and named folders within a single
	 * fetchmail run.  If that assumption ever becomes invalid, the
	 * pop2_getauth code will have to stash the pound response away
	 * explicitly in case it gets stepped on.
	 */
	if (pound_arg == -1)
	    return(PS_ERROR);

    *countp = pound_arg;
    *bytes = *newp = -1;

    return(0);
}

static int pop2_fetch(int sock, struct query *ctl, int number, int *lenp)
/* request nth message */
{
    int	ok;

    *lenp = 0;
    ok = gen_transact(sock, "READ %d", number);
    if (ok)
	return(0);
    *lenp = equal_arg;

    gen_send(sock, "RETR");

    return(ok);
}

static int pop2_trail(int sock, struct query *ctl, int number, const char *tag)
/* send acknowledgement for message data */
{
    return(gen_transact(sock, ctl->keep ? "ACKS" : "ACKD"));
}

static int pop2_logout(int sock, struct query *ctl)
/* send logout command */
{
    return(gen_transact(sock, "QUIT"));
}

static const struct method pop2 =
{
    "POP2",				/* Post Office Protocol v2 */
    109,				/* standard POP2 port */
    109,				/* ssl POP2 port - not */
    FALSE,				/* this is not a tagged protocol */
    FALSE,				/* does not use message delimiter */
    pop2_ok,				/* parse command response */
    pop2_getauth,			/* get authorization */
    pop2_getrange,			/* query range of messages */
    NULL,				/* no way to get sizes */
    NULL,				/* no way to get sizes of subsets */
    NULL,				/* messages are always new */
    pop2_fetch,				/* request given message */
    NULL,				/* no way to fetch body alone */
    pop2_trail,				/* eat message trailer */
    NULL,				/* no POP2 delete method */
    NULL,				/* how to mark a message as seen */
    pop2_logout,			/* log out, we're done */
    FALSE,				/* no, we can't re-poll */
};

int doPOP2 (struct query *ctl)
/* retrieve messages using POP2 */
{
    peek_capable = FALSE;
    return(do_protocol(ctl, &pop2));
}
#endif /* POP2_ENABLE */

/* pop2.c ends here */
