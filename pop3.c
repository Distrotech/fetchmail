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

#include  <sys/time.h>
#include  <ctype.h>
#include  <errno.h>

#include  "socket.h"
#include  "popclient.h"

#define	  POP3_PORT	110

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int POP3_sendSTAT (int *msgcount, int socket);
int POP3_sendLAST (int *last, int socket);
int POP3_sendUIDL (int num, int socket, char **cp);
int POP3_BuildDigest (char *buf, struct hostrec *options);
#endif


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
  char buf [POPBUFSIZE];
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

