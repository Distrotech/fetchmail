/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       pop3.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
		Hacks and bug fixes by esr.
  description:  POP3 client code.

 ***********************************************************************/

#include  <config.h>

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

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int POP3_sendSTAT (int *msgcount, int socket);
int POP3_sendLAST (int *last, int socket);
int POP3_sendUIDL (int num, int socket, char **cp);
int POP3_BuildDigest (char *buf, struct hostrec *options);
#endif


/*********************************************************************

 Method declarations for POP3 

 *********************************************************************/

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
	if (POP3_BuildDigest(greeting,queryctl) != 0) {
	    return(PS_AUTHFAIL);
	}
#endif  /* HAVE_APOP_SUPPORT */

    switch (queryctl->protocol) {
    case P_POP3:
	SockPrintf(socket,"USER %s\r\n",queryctl->remotename);
	if (outlevel == O_VERBOSE)
	    fprintf(stderr,"> USER %s\n",queryctl->remotename);
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;

	if (queryctl->rpopid[0])
	{
	    SockPrintf(socket, "RPOP %s\r\n", queryctl->rpopid);
	    if (outlevel == O_VERBOSE)
		fprintf(stderr,"> RPOP %s %s\n",queryctl->rpopid);
	}
	else
	{
	    SockPrintf(socket,"PASS %s\r\n",queryctl->password);
	    if (outlevel == O_VERBOSE)
		fprintf(stderr,"> PASS password\n");
	}
	if (pop3_ok(buf,socket) != 0)
	    goto badAuth;
	break;

#if defined(HAVE_APOP_SUPPORT)
    case P_APOP:
	SockPrintf(socket,"APOP %s %s\r\n", 
		   queryctl->remotename, queryctl->digest);
	if (outlevel == O_VERBOSE)
	    fprintf(stderr,"> APOP %s %s\n",queryctl->remotename, queryctl->digest);
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
    else
	; /* say nothing */

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

  ok = POP3_sendSTAT(countp,socket);
  if (ok != 0) {
    return(ok);
  }

  /*
   * Ask for number of last message retrieved.  
   * Newer, RFC-1760-conformant POP servers may not have the LAST command.
   * Therefore we don't croak if we get a nonzero return.  Instead, send
   * UIDL and try to find the last received ID stored for this host in
   * the list we get back.
   */
  *firstp = 1;
  use_uidl = 0;
  if (!queryctl->fetchall) {
    char buf [POPBUFSIZE+1];
    char id [IDLEN+1];
    int num;

    /* try LAST first */
    ok = POP3_sendLAST(firstp, socket);
    use_uidl = (ok != 0); 

    /* otherwise, if we have a stored last ID for this host,
     * send UIDL and search the returned list for it
     */ 
    if (use_uidl && queryctl->lastid[0]) {
      if ((ok = POP3_sendUIDL(-1, socket, 0)) == 0) {
          while (SockGets(socket, buf, sizeof(buf)) >= 0) {
	    if (outlevel == O_VERBOSE)
	      fprintf(stderr,"%s\n",buf);
	    if (strcmp(buf, ".\n") == 0) {
              break;
	    }
            if (sscanf(buf, "%d %s\n", &num, id) == 2)
		if (strcmp(id, queryctl->lastid) == 0)
		    *firstp = num;
          }
       }
    }

    if (ok == 0)
      (*firstp)++;
  }

  return(0);
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

static pop3_trail(socket, queryctl, number)
/* update the last-seen field for this host */
int socket;
struct hostrec *queryctl;
int number;
{
    char *cp;
    int	ok = 0;

    if (use_uidl && (ok = POP3_sendUIDL(number, socket, &cp)) == 0)
	(void) strcpy(queryctl->lastid, cp);
    return(ok);
}

static struct method pop3 =
{
    "POP3",				/* Post Office Protocol v3 */
    110,				/* standard POP3 port */
    0,					/* this is not a tagged protocol */
    1,					/* this uses a message delimiter */
    pop3_ok,				/* parse command response */
    pop3_getauth,			/* get authorization */
    pop3_getrange,			/* query range of messages */
    pop3_fetch,				/* request given message */
    pop3_trail,				/* eat message trailer */
    "DELE %d",				/* set POP3 delete flag */
    NULL,				/* the POP3 expunge command */
    "QUIT",				/* the POP3 exit command */
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

/*********************************************************************
  function:      POP3_sendSTAT
  description:   send the STAT command to the POP3 server to find
                 out how many messages are waiting.
  arguments:     
    count        pointer to an integer to receive the message count.
    socket       socket to which the POP3 server is connected.

  return value:  return code from POP3_OK.
  calls:         POP3_OK, SockPrintf
  globals:       reads outlevel.
 *********************************************************************/

int POP3_sendSTAT (msgcount,socket)
int *msgcount;
int socket;
{
  int ok;
  char buf [POPBUFSIZE+1];
  int totalsize;

  SockPrintf(socket,"STAT\r\n");
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> STAT\n");
  
  ok = pop3_ok(buf,socket);
  if (ok == 0)
    sscanf(buf,"%d %d",msgcount,&totalsize);
  else if (outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}

/******************************************************************
  function:	POP3_sendLAST
  description:	send the LAST command to the server, which should
                return the number of the last message number retrieved 
                from the server.
  arguments:
    last	integer buffer to receive last message# 

  ret. value:	zero if success, else status code.
  globals:	SockPrintf, pop3_ok.
  calls:	reads outlevel.
 *****************************************************************/

int POP3_sendLAST (last, socket)
int *last;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];

  SockPrintf(socket,"LAST\r\n");
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> LAST\n");

  ok = pop3_ok(buf,socket);
  if (ok == 0 && sscanf(buf,"%d",last) == 0)
    ok = PS_ERROR;

  if (ok != 0 && outlevel > O_SILENT) 
    fprintf(stderr,"Server says '%s' to LAST command.\n",buf);

  return(ok);
}

/******************************************************************
  function:	POP3_sendUIDL
  description:	send the UIDL command to the server, 

  arguments:
    num 	number of message to query (may be -1)

  ret. value:	zero if success, else status code.
  globals:	SockPrintf, pop3_ok.
  calls:	reads outlevel.
 *****************************************************************/

int POP3_sendUIDL (num, socket, cp)
int num;
int socket;
char **cp;
{
  int ok;
  char buf [POPBUFSIZE];
  static char id[IDLEN];

  (void) strcpy(buf, "UIDL\r\n");
  if (num > -1)
    (void) sprintf(buf, "UIDL %d\r\n", num);
 
  SockPrintf(socket, buf);
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s", buf);

  ok = pop3_ok(buf,socket);
  if (ok != 0 && outlevel > O_SILENT) 
    fprintf(stderr,"Server says '%s' to UIDL command.\n",buf);

  if (cp) {
    sscanf(buf, "%*d %s\n", id);
    *cp = id;
  }
  return(ok);
}


/******************************************************************
  function:	POP3_BuildDigest
  description:	Construct the MD5 digest for the current session,
	        using the user-specified password, and the time
                stamp in the POP3 greeting.
  arguments:
    buf		greeting string
    queryctl	merged options record.

  ret. value:	zero on success, nonzero if no timestamp found in
	        greeting.
  globals:	none.
  calls:	MD5Digest.
 *****************************************************************/

#if defined(HAVE_APOP_SUPPORT)
POP3_BuildDigest (buf,queryctl)
char *buf;
struct hostrec *queryctl;
{
  char *start,*end;
  char *msg;

  /* find start of timestamp */
  for (start = buf;  *start != 0 && *start != '<';  start++)
    ;
  if (*start == 0) {
    fprintf(stderr,"Required APOP timestamp not found in greeting\n");
    return(-1);
  }

  /* find end of timestamp */
  for (end = start;  *end != 0  && *end != '>';  end++)
    ;
  if (*end == 0 || (end - start - 1) == 1) {
    fprintf(stderr,"Timestamp syntax error in greeting\n");
    return(-1);
  }

  /* copy timestamp and password into digestion buffer */
  msg = (char *) malloc((end-start-1) + strlen(queryctl->password) + 1);
  *(++end) = 0;
  strcpy(msg,start);
  strcat(msg,queryctl->password);

  strcpy(queryctl->digest, MD5Digest(msg));
  free(msg);
  return(0);
}
#endif  /* HAVE_APOP_SUPPORT */

