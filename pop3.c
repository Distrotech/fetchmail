/*
 * pop3.c -- POP3 protocol methods
 *
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#include  <string.h>
 
#include  "socket.h"
#include  "fetchmail.h"

static int last;

int pop3_ok (socket, argbuf)
/* parse command response */
int socket;
char *argbuf;
{
  int ok;
  char buf [POPBUFSIZE+1];
  char *bufp;

  if (SockGets(socket, buf, sizeof(buf)) >= 0) {
    if (outlevel == O_VERBOSE)
      fprintf(stderr,"%s\n",buf);

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

int pop3_getauth(socket, queryctl, greeting)
/* apply for connection authorization */
int socket;
struct hostrec *queryctl;
char *greeting;
{
    char buf [POPBUFSIZE+1];

    /* build MD5 digest from greeting timestamp + password */
    if (queryctl->protocol == P_APOP) 
    {
	char *start,*end;
	char *msg;

	/* find start of timestamp */
	for (start = greeting;  *start != 0 && *start != '<';  start++)
	    continue;
	if (*start == 0) {
	    fprintf(stderr,"Required APOP timestamp not found in greeting\n");
	    return(PS_AUTHFAIL);
	}

	/* find end of timestamp */
	for (end = start;  *end != 0  && *end != '>';  end++)
	    continue;
	if (*end == 0 || (end - start - 1) == 1) {
	    fprintf(stderr,"Timestamp syntax error in greeting\n");
	    return(PS_AUTHFAIL);
	}

	/* copy timestamp and password into digestion buffer */
	msg = (char *)xmalloc((end-start-1) + strlen(queryctl->password) + 1);
	*(++end) = 0;
	strcpy(msg,start);
	strcat(msg,queryctl->password);

	strcpy(queryctl->digest, MD5Digest(msg));
	free(msg);
    }

    switch (queryctl->protocol) {
    case P_POP3:
	if ((gen_transact(socket,"USER %s", queryctl->remotename)) != 0)
	    return(PS_ERROR);

	if ((gen_transact(socket, "PASS %s", queryctl->password)) != 0)
	    return(PS_ERROR);
	break;

    case P_APOP:
	if ((gen_transact(socket, "APOP %s %s",
			  queryctl->remotename, queryctl->digest)) != 0)
	    return(PS_ERROR);
	break;

    default:
	fprintf(stderr,"Undefined protocol request in POP3_auth\n");
    }

    /* we're approved */
    return(0);
}

static pop3_getrange(socket, queryctl, countp, newp)
/* get range of messages to be fetched */
int socket;
struct hostrec *queryctl;
int *countp, *newp;
{
    int ok;
    char buf [POPBUFSIZE+1];

    /* Ensure that the new list is properly empty */
    queryctl->newsaved = (struct idlist *)NULL;

    /* get the total message count */
    gen_send(socket, "STAT");
    ok = pop3_ok(socket, buf);
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
    if (*countp > 0 && !queryctl->fetchall)
    {
	char id [IDLEN+1];

	gen_send(socket,"LAST");
	ok = pop3_ok(socket, buf);
	if (ok == 0)
	{
	    if (sscanf(buf, "%d", &last) == 0)
		return(PS_ERROR);
	    *newp = (*countp - last);
	}
 	else
 	{
	    int	num;
	    struct idlist *idp;

 	    /* grab the mailbox's UID list */
	    *newp = 0;
 	    gen_send(socket, "UIDL");
 	    if ((ok = pop3_ok(socket, buf)) == 0) {
 		while (SockGets(socket, buf, sizeof(buf)) >= 0) {
 		    if (outlevel == O_VERBOSE)
 			fprintf(stderr,"%s\n",buf);
 		    if (strcmp(buf, ".") == 0) {
 			break;
 		    }
 		    if (sscanf(buf, "%d %s", &num, id) == 2)
		    {
 			save_uid(&queryctl->newsaved, num, id);
			if (!uid_in_list(&queryctl->oldsaved, id))
			    (*newp)++;
		    }
 		}
 	    }
 	}
    }

    return(0);
}

static int pop3_is_old(socket, queryctl, num)
int socket;
struct hostrec *queryctl;
int num;
{
    if (!queryctl->oldsaved)
	return (num <= last);
    else
        return (uid_in_list(&queryctl->oldsaved,
			    uid_find (&queryctl->newsaved, num)));
}

static int pop3_fetch(socket, number, lenp)
/* request nth message */
int socket;
int number;
int *lenp; 
{
    int ok;
    char buf [POPBUFSIZE+1], *cp;

    gen_send(socket, "RETR %d", number);
    if ((ok = pop3_ok(socket, buf)) != 0)
	return(ok);
    /* look for "nnn octets" -- there may or may not be preceding cruft */
    if ((cp = strstr(buf, " octets")) == (char *)NULL)
	*lenp = 0;
    else
    {
	while (isdigit(*--cp))
	    continue;
	*lenp = atoi(++cp);
    }
    return(0);
}

static pop3_delete(socket, queryctl, number)
/* delete a given message */
int socket;
struct hostrec *queryctl;
int number;
{
    return(gen_transact(socket, "DELE %d", number));
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
    pop3_is_old,	/* how do we tell a message is old? */
    pop3_fetch,		/* request given message */
    NULL,		/* no message trailer */
    pop3_delete,	/* how to delete a message */
    NULL,		/* no POP3 expunge command */
    "QUIT",		/* the POP3 exit command */
};

int doPOP3 (queryctl)
/* retrieve messages using POP3 */
struct hostrec *queryctl;
{
    if (queryctl->mailbox[0]) {
	fprintf(stderr,"Option --remote is not supported with POP3\n");
	return(PS_SYNTAX);
    }
    return(do_protocol(queryctl, &pop3));
}

/* pop3.c ends here */
