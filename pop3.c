/*
 * pop3.c -- POP3 protocol methods
 *
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"

#include  <stdio.h>
#include  <string.h>
#include  <ctype.h>
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
 
#include  "fetchmail.h"
#include  "socket.h"

#define PROTOCOL_ERROR	{error(0, 0, "protocol error"); return(PS_ERROR);}

#define LOCKBUSY_ERROR	{error(0, 0, "lock busy!  Is another session active?"); return(PS_LOCKBUSY);}

extern char *strstr();	/* needed on sysV68 R3V7.1. */

static int last;

int pop3_ok (int sock, char *argbuf)
/* parse command response */
{
    int ok;
    char buf [POPBUFSIZE+1];
    char *bufp;

    if ((ok = gen_recv(sock, buf, sizeof(buf))) == 0)
    {
	bufp = buf;
	if (*bufp == '+' || *bufp == '-')
	    bufp++;
	else
	    return(PS_PROTOCOL);

	while (isalpha(*bufp))
	    bufp++;
	*(bufp++) = '\0';

	if (strcmp(buf,"+OK") == 0)
	    ok = 0;
	else if (strcmp(buf,"-ERR") == 0)
	{
	    /*
	     * We're checking for "lock busy", "unable to lock", 
	     * "already locked" etc. here.  This indicates that we
	     * have to wait for the server to clean up before we
	     * can poll again.
	     *
	     * PS_LOCKBUSY check empirically verified with two recent
	     * versions the Berkeley popper;	QPOP (version 2.2)  and
	     * QUALCOMM Pop server derived from UCB (version 2.1.4-R3)
	     */
	    if (strstr(bufp,"lock")||strstr(bufp,"Lock")||strstr(bufp,"LOCK"))
		ok = PS_LOCKBUSY;
	    else
		ok = PS_ERROR;
	}
	else
	    ok = PS_PROTOCOL;

	if (argbuf != NULL)
	    strcpy(argbuf,bufp);
    }

    return(ok);
}

int pop3_getauth(int sock, struct query *ctl, char *greeting)
/* apply for connection authorization */
{
    int ok;

    /* build MD5 digest from greeting timestamp + password */
    if (ctl->server.protocol == P_APOP) 
    {
	char *start,*end;
	char *msg;

	/* find start of timestamp */
	for (start = greeting;  *start != 0 && *start != '<';  start++)
	    continue;
	if (*start == 0) {
	    error(0, -1, "Required APOP timestamp not found in greeting");
	    return(PS_AUTHFAIL);
	}

	/* find end of timestamp */
	for (end = start;  *end != 0  && *end != '>';  end++)
	    continue;
	if (*end == 0 || end == start + 1) {
	    error(0, -1, "Timestamp syntax error in greeting");
	    return(PS_AUTHFAIL);
	}
	else
	    *++end = '\0';

	/* copy timestamp and password into digestion buffer */
	msg = (char *)xmalloc((end-start+1) + strlen(ctl->password) + 1);
	strcpy(msg,start);
	strcat(msg,ctl->password);

	strcpy(ctl->digest, MD5Digest(msg));
	free(msg);
    }

    switch (ctl->server.protocol) {
    case P_POP3:
	if ((gen_transact(sock, "USER %s", ctl->remotename)) != 0)
	    PROTOCOL_ERROR

	if ((ok = gen_transact(sock, "PASS %s", ctl->password)) != 0)
	{
	    if (ok == PS_LOCKBUSY)
		LOCKBUSY_ERROR
	    PROTOCOL_ERROR
	}

	/*
	 * Empirical experience shows some server/OS combinations
	 * may need a brief pause even after any lockfiles on the
	 * server are released, to give the server time to finish
	 * copying back very large mailfolders from the temp-file...
	 * this is only ever an issue with extremely large mailboxes.
	 */
	sleep(3); /* to be _really_ safe, probably need sleep(5)! */
	break;

    case P_APOP:
	if ((gen_transact(sock, "APOP %s %s",
			  ctl->remotename, ctl->digest)) != 0)
	    PROTOCOL_ERROR
	break;

    case P_RPOP:
	if ((gen_transact(sock,"USER %s", ctl->remotename)) != 0)
	    PROTOCOL_ERROR

	if ((gen_transact(sock, "RPOP %s", ctl->password)) != 0)
	    PROTOCOL_ERROR
	break;

    default:
	error(0, 0, "Undefined protocol request in POP3_auth");
    }

    /* we're approved */
    return(0);
}

static int pop3_getrange(int sock, 
			 struct query *ctl,
			 const char *folder,
			 int *countp, int *newp)
/* get range of messages to be fetched */
{
    int ok;
    char buf [POPBUFSIZE+1];

    /* Ensure that the new list is properly empty */
    ctl->newsaved = (struct idlist *)NULL;

    /* get the total message count */
    gen_send(sock, "STAT");
    ok = pop3_ok(sock, buf);
    if (ok == 0)
	sscanf(buf,"%d %*d", countp);
    else
	return(ok);

    /*
     * Newer, RFC-1725-conformant POP servers may not have the LAST command.
     * We work as hard as possible to hide this ugliness, but it makes 
     * counting new messages intrinsically quadratic in the worst case.
     */
    last = 0;
    *newp = -1;
    if (*countp > 0 && !ctl->fetchall)
    {
	char id [IDLEN+1];

	if (!ctl->server.uidl) {
	    gen_send(sock, "LAST");
	    ok = pop3_ok(sock, buf);
	} else
	    ok = 1;
	if (ok == 0)
	{
	    if (sscanf(buf, "%d", &last) == 0)
		PROTOCOL_ERROR
	    *newp = (*countp - last);
	}
 	else
 	{
 	    /* grab the mailbox's UID list */
 	    if ((ok = gen_transact(sock, "UIDL")) != 0)
		PROTOCOL_ERROR
	    else
	    {
		int	num;

		*newp = 0;
 		while ((ok = gen_recv(sock, buf, sizeof(buf))) == 0)
		{
 		    if (buf[0] == '.')
 			break;
 		    else if (sscanf(buf, "%d %s", &num, id) == 2)
		    {
 			save_str(&ctl->newsaved, num, id);

			/* note: ID comparison is caseblind */
			if (!str_in_list(&ctl->oldsaved, id))
			    (*newp)++;
		    }
 		}
 	    }
 	}
    }

    return(0);
}

static int pop3_getsizes(int sock, int count, int *sizes)
/* capture the sizes of all messages */
{
    int	ok;

    if ((ok = gen_transact(sock, "LIST")) != 0)
	return(ok);
    else
    {
	char buf [POPBUFSIZE+1];

	while ((ok = gen_recv(sock, buf, sizeof(buf))) == 0)
	{
	    int num, size;

	    if (buf[0] == '.')
		break;
	    else if (sscanf(buf, "%d %d", &num, &size) == 2)
		sizes[num - 1] = size;
	    else
		sizes[num - 1] = -1;
	}

	return(ok);
    }
}

static int pop3_is_old(int sock, struct query *ctl, int num)
/* is the given message old? */
{
    if (!ctl->oldsaved)
	return (num <= last);
    else
	/* note: ID comparison is caseblind */
        return (str_in_list(&ctl->oldsaved,
			    str_find (&ctl->newsaved, num)));
}

static int pop3_fetch(int sock, struct query *ctl, int number, int *lenp)
/* request nth message */
{
    int ok;
    char buf [POPBUFSIZE+1], *cp;

    gen_send(sock, "RETR %d", number);
    if ((ok = pop3_ok(sock, buf)) != 0)
	return(ok);

    /* 
     * Look for "nnn octets" -- there may or may not be preceding cruft.
     * It's OK to punt and pass back -1 as a failure indication here, as 
     * long as the force_getsizes flag has forced sizes to be preloaded.
     */
    if ((cp = strstr(buf, " octets")) == (char *)NULL)
	*lenp = -1;
    else
    {
	while (--cp >= buf && isdigit(*cp))
	    continue;
	*lenp = atoi(++cp);
    }

    return(0);
}

static int pop3_delete(int sock, struct query *ctl, int number)
/* delete a given message */
{
    return(gen_transact(sock, "DELE %d", number));
}

const static struct method pop3 =
{
    "POP3",		/* Post Office Protocol v3 */
    110,		/* standard POP3 port */
    FALSE,		/* this is not a tagged protocol */
    TRUE,		/* this uses a message delimiter */
    TRUE,		/* RFC 1725 doesn't require a size field in fetch */
    pop3_ok,		/* parse command response */
    pop3_getauth,	/* get authorization */
    pop3_getrange,	/* query range of messages */
    pop3_getsizes,	/* we can get a list of sizes */
    pop3_is_old,	/* how do we tell a message is old? */
    pop3_fetch,		/* request given message */
    NULL,		/* no way to fetch body alone */
    NULL,		/* no message trailer */
    pop3_delete,	/* how to delete a message */
    "QUIT",		/* the POP3 exit command */
};

int doPOP3 (struct query *ctl)
/* retrieve messages using POP3 */
{
    if (ctl->mailboxes->id) {
	fprintf(stderr,"Option --remote is not supported with POP3\n");
	return(PS_SYNTAX);
    }
    peek_capable = FALSE;
    return(do_protocol(ctl, &pop3));
}

/* pop3.c ends here */
