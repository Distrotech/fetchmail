/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       pop3.c
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
		Hacks and bug fixes by esr.
  description:  POP3 client code.

 ***********************************************************************/

#include  <config.h>
#include  <stdio.h>
#include  "socket.h"
#include  "fetchmail.h"

int pop3_ok (argbuf,socket)
/* parse command response */
char *argbuf;
int socket;
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

#if defined(HAVE_APOP_SUPPORT)
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
	msg = (char *) malloc((end-start-1) + strlen(queryctl->password) + 1);
	*(++end) = 0;
	strcpy(msg,start);
	strcat(msg,queryctl->password);

	strcpy(queryctl->digest, MD5Digest(msg));
	free(msg);
    }
#endif  /* HAVE_APOP_SUPPORT */

    switch (queryctl->protocol) {
    case P_POP3:
	gen_send(socket,"USER %s", queryctl->remotename);
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;

	gen_send(socket, "PASS %s", queryctl->password);
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;
	break;

    case P_RPOP:
	gen_send(socket,"USER %s", queryctl->remotename);
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;

	gen_send(socket, "RPOP %s", queryctl->password);
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;
	break;

#if defined(HAVE_APOP_SUPPORT)
    case P_APOP:
	gen_send(socket,"APOP %s %s", queryctl->remotename, queryctl->digest);
	if (pop3_ok(buf,socket) != 0) 
	    goto badAuth;
	break;
#endif  /* HAVE_APOP_SUPPORT */

    default:
	fprintf(stderr,"Undefined protocol request in POP3_auth\n");
    }

    /* we're approved */
    return(0);

    /*NOTREACHED*/

badAuth:
    if (outlevel > O_SILENT && outlevel < O_VERBOSE)
	fprintf(stderr,"%s\n",buf);
    return(PS_ERROR);
}

static int use_uidl;

static pop3_getrange(socket, queryctl, countp, firstp)
/* get range of messages to be fetched */
int socket;
struct hostrec *queryctl;
int *countp;
int *firstp;
{
    int ok;
    char buf [POPBUFSIZE+1];

    /* get the total message count */
    gen_send(socket, "STAT");
    ok = pop3_ok(buf,socket);
    if (ok == 0)
	sscanf(buf,"%d %*d", countp);
    else
	return(ok);

    /*
     * Ask for number of last message retrieved.  
     * Newer, RFC-1760-conformant POP servers may not have the LAST command.
     * Therefore we don't croak if we get a nonzero return.  Instead, send
     * UIDL and try to find the last received ID stored for this host in
     * the list we get back.
     */
    *firstp = 1;
    use_uidl = 0;
    if (*countp > 0 && !queryctl->fetchall) {
	char id [IDLEN+1];
	int num;

	/* try LAST first */
	gen_send(socket,"LAST");
	ok = pop3_ok(buf,socket);
	if (ok == 0 && sscanf(buf, "%d", &num) == 0)
	    return(PS_ERROR);

	use_uidl = (ok != 0); 

	if (!use_uidl)
	    *firstp = num + 1;
	else
	{
	    /* grab the mailbox's UID list */
	    gen_send(socket, "UIDL");
	    if ((ok = pop3_ok(buf, socket)) == 0) {
		while (SockGets(socket, buf, sizeof(buf)) >= 0) {
		    if (outlevel == O_VERBOSE)
			fprintf(stderr,"%s\n",buf);
		    if (strcmp(buf, ".\n") == 0) {
			break;
		    }
		    if (sscanf(buf, "%d %s\n", &num, id) == 2)
			save_uid(&queryctl->mailbox, num, id);
		}
	    }
	}
    }

    return(0);
}

static pop3_is_old(socket, queryctl, number)
/* check a given message for age by UID */
int socket;
struct hostrec *queryctl;
int number;
{
    if (!use_uidl)
	return(0);
    else
    {
	char buf [POPBUFSIZE+1];
	int ok;

	gen_send(socket, "UIDL %d", number);
	if ((ok = pop3_ok(socket, buf)) != 0)
	    return(ok);
	else
	{
	    char	id[IDLEN+1];

	    if (sscanf(buf, "%*d %s", id) == 2)
		return(uid_in_list(&queryctl->saved, id));
	    else
		return(0);
	}
    }
}

static int pop3_fetch(socket, number, limit, lenp)
/* request nth message */
int socket;
int number;
int limit;
int *lenp; 
{
    *lenp = 0;
    if (limit) 
        return(gen_transact(socket, "TOP %d %d", number, limit));
      else 
        return(gen_transact(socket, "RETR %d", number));
}

static pop3_delete(socket, queryctl, number)
/* delete a given message */
int socket;
struct hostrec *queryctl;
int number;
{
    int	ok;

    /* send the deletion request */
    if ((ok = gen_transact(socket, "DELE %d", number)) != 0)
	return(ok);

    /* we may need to nuke the message's UID out of the mailbox list */
    if (use_uidl)
    {
	char buf [POPBUFSIZE+1];

	/*
	 * This isn't strictly necessary.  We should probably just
	 * stash the UID result from the last is_old call.
	 */
	gen_send(socket, "UIDL %d", number);
	if ((ok = pop3_ok(socket, buf)) != 0)
	    return(ok);
	else
	{
	    char	id[IDLEN+1];

	    if (sscanf(buf, "%*d %s", id) == 2)
		delete_uid(&queryctl->mailbox, id); 
	    return(0);
	}
    }
}

static struct method pop3 =
{
    "POP3",		/* Post Office Protocol v3 */
    110,		/* standard POP3 port */
    0,			/* this is not a tagged protocol */
    1,			/* this uses a message delimiter */
    pop3_ok,		/* parse command response */
    pop3_getauth,	/* get authorization */
    pop3_getrange,	/* query range of messages */
    pop3_is_old,	/* check for age by UID */
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
    if (queryctl->remotefolder[0]) {
	fprintf(stderr,"Option --remote is not supported with POP3\n");
	return(PS_SYNTAX);
    }

    return(do_protocol(queryctl, &pop3));
}


