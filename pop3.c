/*
 * pop3.c -- POP3 protocol methods
 *
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>

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

#define PROTOCOL_ERROR	{error(0, 0, "protocol error"); return(PS_ERROR);}

static int last;

int pop3_ok (FILE *sockfp, char *argbuf)
/* parse command response */
{
    int ok;
    char buf [POPBUFSIZE+1];
    char *bufp;

    if (fgets(buf, sizeof(buf), sockfp)) {
	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\r';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "POP3< %s", buf);

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
	    ok = PS_ERROR;
	else
	    ok = PS_PROTOCOL;

	if (argbuf != NULL)
	    strcpy(argbuf,bufp);
    }
    else 
	ok = PS_SOCKET;

    return(ok);
}

int pop3_getauth(FILE *sockfp, struct query *ctl, char *greeting)
/* apply for connection authorization */
{
    /* build MD5 digest from greeting timestamp + password */
    if (ctl->protocol == P_APOP) 
    {
	char *start,*end;
	char *msg;

	/* find start of timestamp */
	for (start = greeting;  *start != 0 && *start != '<';  start++)
	    continue;
	if (*start == 0) {
	    error(0, 0, "Required APOP timestamp not found in greeting");
	    return(PS_AUTHFAIL);
	}

	/* find end of timestamp */
	for (end = start;  *end != 0  && *end != '>';  end++)
	    continue;
	if (*end == 0 || end == start + 1) {
	    error(0, 0, "Timestamp syntax error in greeting");
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

    switch (ctl->protocol) {
    case P_POP3:
	if ((gen_transact(sockfp,"USER %s", ctl->remotename)) != 0)
	    PROTOCOL_ERROR

	if ((gen_transact(sockfp, "PASS %s", ctl->password)) != 0)
	    PROTOCOL_ERROR
	break;

    case P_APOP:
	if ((gen_transact(sockfp, "APOP %s %s",
			  ctl->remotename, ctl->digest)) != 0)
	    PROTOCOL_ERROR
	break;

    default:
	error(0, 0, "Undefined protocol request in POP3_auth");
    }

    /* we're approved */
    return(0);
}

static int pop3_getrange(FILE *sockfp, struct query *ctl, int*countp, int*newp)
/* get range of messages to be fetched */
{
    int ok;
    char buf [POPBUFSIZE+1];

    /* Ensure that the new list is properly empty */
    ctl->newsaved = (struct idlist *)NULL;

    /* get the total message count */
    gen_send(sockfp, "STAT");
    ok = pop3_ok(sockfp, buf);
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

	gen_send(sockfp,"LAST");
	ok = pop3_ok(sockfp, buf);
	if (ok == 0)
	{
	    if (sscanf(buf, "%d", &last) == 0)
		PROTOCOL_ERROR
	    *newp = (*countp - last);
	}
 	else
 	{
 	    /* grab the mailbox's UID list */
 	    if ((ok = gen_transact(sockfp, "UIDL")) != 0)
		PROTOCOL_ERROR
	    else
	    {
		int	num;

		*newp = 0;
 		while (fgets(buf, sizeof(buf), sockfp))
		{
		    if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';
		    if (buf[strlen(buf)-1] == '\r')
			buf[strlen(buf)-1] = '\r';
 		    if (outlevel == O_VERBOSE)
			error(0, 0, "POP3< %s", buf);
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

static int pop3_getsizes(FILE *sockfp, int count, int *sizes)
/* capture the sizes of all messages */
{
    int	ok;

    if ((ok = gen_transact(sockfp, "LIST")) != 0)
	return(ok);
    else
    {
	char buf [POPBUFSIZE+1];

	while (fgets(buf, sizeof(buf), sockfp))
	{
	    int num, size;

	    if (buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = '\0';
	    if (buf[strlen(buf)-1] == '\r')
		buf[strlen(buf)-1] = '\r';
	    if (outlevel == O_VERBOSE)
		error(0, 0, "POP3< %s", buf);
	    if (buf[0] == '.')
		break;
	    else if (sscanf(buf, "%d %d", &num, &size) == 2)
		sizes[num - 1] = size;
	    else
		sizes[num - 1] = -1;
	}

	return(0);
    }
}

static int pop3_is_old(FILE *sockfp, struct query *ctl, int num)
/* is the given message old? */
{
    if (!ctl->oldsaved)
	return (num <= last);
    else
	/* note: ID comparison is caseblind */
        return (str_in_list(&ctl->oldsaved,
			    str_find (&ctl->newsaved, num)));
}

static int pop3_fetch(FILE *sockfp, int number, int *lenp)
/* request nth message */
{
    int ok;
    char buf [POPBUFSIZE+1], *cp;

    gen_send(sockfp, "RETR %d", number);
    if ((ok = pop3_ok(sockfp, buf)) != 0)
	return(ok);
    /* look for "nnn octets" -- there may or may not be preceding cruft */
    if ((cp = strstr(buf, " octets")) == (char *)NULL)
	*lenp = 0;
    else
    {
	while (--cp > buf && isdigit(*cp))
	    continue;
	*lenp = atoi(cp);
    }
    return(0);
}

static int pop3_delete(FILE *sockfp, struct query *ctl, int number)
/* delete a given message */
{
    return(gen_transact(sockfp, "DELE %d", number));
}

const static struct method pop3 =
{
    "POP3",		/* Post Office Protocol v3 */
    110,		/* standard POP3 port */
    0,			/* this is not a tagged protocol */
    1,			/* this uses a message delimiter */
    pop3_ok,		/* parse command response */
    pop3_getauth,	/* get authorization */
    pop3_getrange,	/* query range of messages */
    pop3_getsizes,	/* we can get a list of sizes */
    pop3_is_old,	/* how do we tell a message is old? */
    pop3_fetch,		/* request given message */
    NULL,		/* no message trailer */
    pop3_delete,	/* how to delete a message */
    NULL,		/* no POP3 expunge command */
    "QUIT",		/* the POP3 exit command */
};

int doPOP3 (struct query *ctl)
/* retrieve messages using POP3 */
{
    if (ctl->mailbox[0]) {
	fprintf(stderr,"Option --remote is not supported with POP3\n");
	return(PS_SYNTAX);
    }
    peek_capable = FALSE;
    return(do_protocol(ctl, &pop3));
}

/* pop3.c ends here */
