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
int POP3_OK (char *buf, int socket);
int POP3_auth (struct hostrec *options, int socket);
int POP3_sendQUIT (int socket);
int POP3_sendSTAT (int *msgcount, int socket);
int POP3_sendRETR (int msgnum, int socket);
int POP3_sendDELE (int msgnum, int socket);
int POP3_sendLAST (int *last, int socket);
int POP3_readmsg (int socket, int mboxfd, char *host, int topipe, int rewrite);
int POP3_BuildDigest (char *buf, struct hostrec *options);
#endif


/*********************************************************************
  function:      doPOP3
  description:   retrieve messages from the specified mail server
                 using Post Office Protocol 3.

  arguments:     
    queryctl     fully-specified options (i.e. parsed, defaults invoked,
                 etc).

  return value:  exit code from the set of PS_.* constants defined in 
                 popclient.h
  calls:
  globals:       reads outlevel.
 *********************************************************************/

int doPOP3 (queryctl)
struct hostrec *queryctl;
{
  int ok;
  int mboxfd;
  char buf [POPBUFSIZE];
  int socket;
  int first,number,count;


  /* open stdout or the mailbox, locking it if it is a folder */
  if (queryctl->output == TO_FOLDER || queryctl->output == TO_STDOUT) 
    if ((mboxfd = openuserfolder(queryctl)) < 0) 
      return(PS_IOERR);
    
  /* open the socket and get the greeting */
  if ((socket = Socket(queryctl->servername,POP3_PORT)) < 0) {
    perror("doPOP3: socket");
    ok = PS_SOCKET;
    goto closeUp;
  }

  ok = POP3_OK(buf,socket);
  if (ok != 0) {
    if (ok != PS_SOCKET)
      POP3_sendQUIT(socket);
    close(socket);
    goto closeUp;
  }

  /* print the greeting */
  if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
    fprintf(stderr,"%s\n",buf);
  else 
    ;

#if defined(HAVE_APOP_SUPPORT)
  /* build MD5 digest from greeting timestamp + password */
  if (queryctl->whichpop == P_APOP) 
    if (POP3_BuildDigest(buf,queryctl) != 0) {
      ok = PS_AUTHFAIL;
      goto closeUp;
    } else
      ;
  else
    ;  /* not using APOP protocol this time */
#endif

  /* try to get authorized */
  ok = POP3_auth(queryctl,socket);
  if (ok == PS_ERROR)
    ok = PS_AUTHFAIL;
  if (ok != 0)
    goto cleanUp;

  /* find out how many messages are waiting */
  ok = POP3_sendSTAT(&count,socket);
  if (ok != 0) {
    goto cleanUp;
  }

  /* Ask for number of last message retrieved */
  if (queryctl->fetchall) 
    first = 1;
  else {
    ok = POP3_sendLAST(&first, socket);
    if (ok != 0)
      goto cleanUp;

    first++;
  }
    
  /* show them how many messages we'll be downloading */
  if (outlevel > O_SILENT && outlevel < O_VERBOSE)
    if (first > 1) 
      fprintf(stderr,"%d messages in folder, %d new messages.\n", 
                      count, count - first + 1);
    else
      fprintf(stderr,"%d new messages in folder.\n", count);
  else
    ;

  if (count > 0) { 
    for (number = (queryctl->flush || queryctl->fetchall)? 1 : first;  
                   number <= count;  
                   number++) {

      /* open the mail pipe if we're using an MDA */
      if (queryctl->output == TO_MDA
           && (queryctl->fetchall || number >= first)) {
        ok = (mboxfd = openmailpipe(queryctl)) < 0 ? -1 : 0;
        if (ok != 0)
          goto cleanUp;
      }
           
      if (queryctl->flush && number < first && !queryctl->fetchall) 
        ok = 0;  /* no command to send here, will delete message below */
      else if (linelimit) 
        ok = POP3_sendTOP(number,linelimit,socket);
      else 
        ok = POP3_sendRETR(number,socket);
      if (ok != 0)
        goto cleanUp;
      
      if (number >= first || queryctl->fetchall)
        ok = POP3_readmsg(socket,mboxfd,
			  queryctl->servername,
			  queryctl->output == TO_MDA, 
			  queryctl->rewrite);
      else
        ok = 0;
      if (ok != 0)
        goto cleanUp;

      if ((number < first && queryctl->flush) || !queryctl->keep) {
        if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
          fprintf(stderr,"flushing message %d\n", number);
        else
          ;
        ok = POP3_sendDELE(number,socket);
        if (ok != 0)
          goto cleanUp;
      }
      else
        ; /* message is kept */

      /* close the mail pipe if we're using the system mailbox */
      if (queryctl->output == TO_MDA
           && (queryctl->fetchall || number >= first)) {
        ok = closemailpipe(mboxfd);
        if (ok != 0)
          goto cleanUp;
      }
    }

    ok = POP3_sendQUIT(socket);
    if (ok == 0)
      ok = PS_SUCCESS;
    close(socket);
    goto closeUp;
  }
  else {
    ok = POP3_sendQUIT(socket);
    if (ok == 0)
      ok = PS_NOMAIL;
    close(socket);
    goto closeUp;
  }

cleanUp:
  if (ok != 0 && ok != PS_SOCKET)
    POP3_sendQUIT(socket);

closeUp:
  if (queryctl->output == TO_FOLDER)
    if (closeuserfolder(mboxfd) < 0 && ok == 0)
      ok = PS_IOERR;
    
  if (ok == PS_IOERR || ok == PS_SOCKET) 
    perror("doPOP3: cleanUp");

  return(ok);
}



/*********************************************************************
  function:      POP3_OK
  description:   get the server's response to a command, and return
                 the extra arguments sent with the response.
  arguments:     
    argbuf       buffer to receive the argument string.
    socket       socket to which the server is connected.

  return value:  zero if okay, else return code.
  calls:         SockGets
  globals:       reads outlevel.
 *********************************************************************/

int POP3_OK (argbuf,socket)
char *argbuf;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];
  char *bufp;

  if (SockGets(socket, buf, sizeof(buf)) == 0) {
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



/*********************************************************************
  function:      POP3_auth
  description:   send the USER and PASS commands to the server, and
                 get the server's response.
  arguments:     
    queryctl	 merged options record.
    socket       socket to which the server is connected.

  return value:  zero if success, else status code.
  calls:         SockPrintf, POP3_OK.
  globals:       read outlevel.
 *********************************************************************/

int POP3_auth (queryctl,socket) 
struct hostrec *queryctl;
int socket;
{
  char buf [POPBUFSIZE];

  switch (queryctl->protocol) {
    case P_POP3:
      SockPrintf(socket,"USER %s\r\n",queryctl->remotename);
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"> USER %s\n",queryctl->remotename);
      if (POP3_OK(buf,socket) != 0)
        goto badAuth;

      SockPrintf(socket,"PASS %s\r\n",queryctl->password);
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"> PASS password\n");
      if (POP3_OK(buf,socket) != 0)
        goto badAuth;
    
      break;

#if defined(HAVE_APOP_SUPPORT)
    case P_APOP:
      SockPrintf(socket,"APOP %s %s\r\n", 
                 queryctl->remotename, queryctl->digest);
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"> APOP %s %s\n",queryctl->remotename, queryctl->digest);
      if (POP3_OK(buf,socket) != 0) 
        goto badAuth;
      break;
#endif  /* HAVE_APOP_SUPPORT */

#if defined(HAVE_RPOP_SUPPORT)
    case P_RPOP:
      SockPrintf(socket, "RPOP %s\r\n", queryctl->remotename);
      if (POP3_OK(buf,socket) != 0)
         goto badAuth;
      if (outlevel == O_VERBOSE)
        fprintf(stderr,"> RPOP %s %s\n",queryctl->remotename);
      break;
#endif  /* HAVE_RPOP_SUPPORT */

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




/*********************************************************************
  function:      POP3_sendQUIT
  description:   send the QUIT command to the server and close 
                 the socket.

  arguments:     
    socket       socket to which the server is connected.

  return value:  none.
  calls:         SockPuts, POP3_OK.
  globals:       reads outlevel.
 *********************************************************************/

int POP3_sendQUIT (socket)
int socket;
{
  int ok;
  char buf [POPBUFSIZE];

  SockPuts(socket,"QUIT");

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> QUIT\n");
  else
    ;

  ok = POP3_OK(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
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
  char buf [POPBUFSIZE];
  int totalsize;

  SockPrintf(socket,"STAT\r\n");
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> STAT\n");
  
  ok = POP3_OK(buf,socket);
  if (ok == 0)
    sscanf(buf,"%d %d",msgcount,&totalsize);
  else if (outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}




/*********************************************************************
  function:      POP3_sendRETR
  description:   send the RETR command to the POP3 server.
  arguments:     
    msgnum       message ID number
    socket       socket to which the POP3 server is connected.

  return value:  return code from POP3_OK.
  calls:         POP3_OK, SockPrintf
  globals:       reads outlevel.
 *********************************************************************/

int POP3_sendRETR (msgnum,socket)
int msgnum;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];

  SockPrintf(socket,"RETR %d\r\n",msgnum);
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> RETR %d\n",msgnum);
  
  ok = POP3_OK(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}


/*********************************************************************
  function:      POP3_sendTOP
  description:   send the TOP command to the POP3 server.
  arguments:     
    msgnum       message ID number
    limit        maximum number of message body lines to retrieve.
    socket       socket to which the POP3 server is connected.

  return value:  return code from POP3_OK.
  calls:         POP3_OK, SockPrintf
  globals:       reads outlevel.
 *********************************************************************/

int POP3_sendTOP (msgnum,limit,socket)
int msgnum;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];

  SockPrintf(socket,"TOP %d %d\r\n",msgnum,limit);
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> TOP %d %d\n",msgnum,limit);
  
  ok = POP3_OK(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"option --limit failed; server says '%s'\n",buf);

  return(ok);
}




/*********************************************************************
  function:      POP3_sendDELE
  description:   send the DELE command to the POP3 server.
  arguments:     
    msgnum       message ID number
    socket       socket to which the POP3 server is connected.

  return value:  return code from POP3_OK.
  calls:         POP3_OK, SockPrintF.
  globals:       reads outlevel.
 *********************************************************************/

int POP3_sendDELE (msgnum,socket)
int msgnum;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];

  SockPrintf(socket,"DELE %d\r\n",msgnum);
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> DELE %d\n",msgnum);
  
  ok = POP3_OK(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}



/*********************************************************************
  function:      POP3_readmsg
  description:   Read the message content as described in RFC 1225.
  arguments:     
    socket       ... to which the server is connected.
    mboxfd       open file descriptor to which the retrieved message will
                 be written. 
    pophost      name of the POP host 
    topipe       true if we're writing to the system mailbox pipe.

  return value:  zero if success else PS_* return code.
  calls:         SockGets.
  globals:       reads outlevel. 
 *********************************************************************/

int POP3_readmsg (socket,mboxfd,pophost,topipe,rewrite)
int socket;
int mboxfd;
char *pophost;
int topipe;
int rewrite;
{ 
  char buf [MSGBUFSIZE]; 
  char *bufp;
  char savec;
  char fromBuf[MSGBUFSIZE];
  int needFrom;
  int inheaders;
  int lines,sizeticker;
  time_t now;
  /* This keeps the retrieved message count for display purposes */
  static int msgnum = 0;  

  /* set up for status message if outlevel allows it */
  if (outlevel > O_SILENT && outlevel < O_VERBOSE) {
    fprintf(stderr,"reading message %d",++msgnum);
    /* won't do the '...' if retrieved messages are being sent to stdout */
    if (mboxfd == 1)
      fputs(".\n",stderr);
    else
      ;
  }
  else
    ;

  /* read the message content from the server */
  inheaders = 1;
  lines = 0;
  sizeticker = MSGBUFSIZE;
  while (1) {
    if (SockGets(socket,buf,sizeof(buf)) < 0)
      return(PS_SOCKET);
    bufp = buf;
    if (buf[0] == '\r' || buf[0] == '\n')
      inheaders = 0;
    if (*bufp == '.') {
      bufp++;
      if (*bufp == 0)
        break;  /* end of message */
    }
    strcat(bufp,"\n");
     
    /* Check for Unix 'From' header, and add a bogus one if it's not
       present -- only if not using an MDA.
       XXX -- should probably parse real From: header and use its 
              address field instead of bogus 'POPmail' string. 
    */
    if (!topipe && lines == 0) {
      if (strlen(bufp) >= strlen("From ")) {
        savec = *(bufp + 5);
        *(bufp + 5) = 0;
        needFrom = strcmp(bufp,"From ") != 0;
        *(bufp + 5) = savec;
      }
      else
        needFrom = 1;
      if (needFrom) {
        now = time(NULL);
        sprintf(fromBuf,"From POPmail %s",ctime(&now));
        if (write(mboxfd,fromBuf,strlen(fromBuf)) < 0) {
          perror("POP3_readmsg: write");
          return(PS_IOERR);
        }
      }
    }

    /*
     * Edit some headers so that replies will work properly.
     */
    if (inheaders && rewrite)
      reply_hack(bufp, pophost);

    /* write this line to the file */
    if (write(mboxfd,bufp,strlen(bufp)) < 0) {
      perror("POP3_readmsg: write");
      return(PS_IOERR);
    }

    sizeticker -= strlen(bufp);
    if (sizeticker <= 0) {
      if (outlevel > O_SILENT && outlevel < O_VERBOSE && mboxfd != 1)
        fputc('.',stderr);
      sizeticker = MSGBUFSIZE;
    }
    lines++;
  }

  if (!topipe) {
    /* The server may not write the extra newline required by the Unix
       mail folder format, so we write one here just in case */
    if (write(mboxfd,"\n",1) < 0) {
      perror("POP3_readmsg: write");
      return(PS_IOERR);
    }
  }
  else {
    /* The mail delivery agent may require a terminator.  Write it if
       it has been defined */
#ifdef BINMAIL_TERM
    if (write(mboxfd,BINMAIL_TERM,strlen(BINMAIL_TERM)) < 0) {
      perror("POP3_readmsg: write");
      return(PS_IOERR);
    }
#endif
    }

  /* finish up display output */
  if (outlevel == O_VERBOSE)
    fprintf(stderr,"(%d lines of message content)\n",lines);
  else if (outlevel > O_SILENT && mboxfd != 1) 
    fputs(".\n",stderr);
  else
    ;
  return(0);
}




/******************************************************************
  function:	POP3_sendLAST
  description:	send the LAST command to the server, which should
                return the number of the last message number retrieved 
                from the server.
  arguments:
    last	integer buffer to receive last message# 

  ret. value:	non-zero on success, else zero.
  globals:	SockPrintf, POP3_OK.
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

  ok = POP3_OK(buf,socket);
  if (ok == 0 && sscanf(buf,"%d",last) == 0)
    ok = PS_ERROR;

  if (ok != 0 && outlevel > O_SILENT) 
    fprintf(stderr,"Server says '%s' to LAST command.\n",buf);

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

