/* Copyright 1996 Harry Hochheiser
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       smtp.c
  project:      popforward
  programmer:   Harry Hochheiser
  description:  Handling of SMTP connections, and processing of mail 
                 to be forwarded via SMTP connections.

  7/30/96.  Note: since this file is new from scratch, I'll assume
  that  I'm working on a modern (ANSI) compiler, and I'll use
  prototypes.


 ***********************************************************************/

#include <config.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "socket.h"
#include "popforward.h"
#include "smtp.h"

static int POP3_parseHeaders(int number, int socket,char **from,int *replFlag);
static int SMTP_sendMessageHeaders(int mboxfd,struct optrec *option,
				   char *from);
static int SendData(int f,char *buf,int check);


/*********************************************************************
  function:      SMTP_helo
  description:   Send a "HELO" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  Result of SMTP_OK: based on codes in popforward.h.
                 
 *********************************************************************/

int SMTP_helo(int socket,char *host)
{
  int ok;
  char buf[SMTPBUFSIZE];
  sprintf(buf,"HELO %s\r\n",host);
  SockPrintf(socket,"%s",buf);
  ok = SMTP_ok(socket,buf);
  return ok;
}


/*********************************************************************
  function:      SMTP_from
  description:   Send a "MAIL FROM:" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
    fromuser:    user name of originator
    fromhost:    host name of originator.  

    Note: these args are likely to change, as we get fancier about
    handling the names.

  return value:  Result of SMTP_ok: based on codes in popforward.h.
                 
 *********************************************************************/
int SMTP_from(int socket,char *fromuser,char *fromhost)
{
  char buf[SMTPBUFSIZE];  /* it's as good as size as any... */
  int ok;
  SockPrintf(socket,"MAIL FROM %s@%s\n",fromuser,fromhost);
  ok= SMTP_ok(socket,buf);

  return ok;
}


/*********************************************************************
  function:      SMTP_rcpt
  description:   Send a "RCPT TO:" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
    toser:    user name of recipient
    tohost:    host name of recipient

  return value:  Result of SMTP_OK: based on codes in popforward.h.
                 
 *********************************************************************/
int SMTP_rcpt(int socket,char *touser,char *tohost)
{
  char buf[SMTPBUFSIZE];  /* it's as good as size as any... */
  int ok;

  SockPrintf(socket,"RCPT TO: %s@%s\n",touser,tohost);
  ok = SMTP_ok(socket,buf);
  
  return ok;
}


/*********************************************************************
  function:      SMTP_data
  description:   Send a "DATA" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP

  return value:  Result of SMTP_OK: based on codes in popforward.h.
                 
 *********************************************************************/
int SMTP_data(int socket)
{
  SockPrintf(socket,"DATA\n");
}


/*********************************************************************
  function:      SMTP_rset
  description:   Send a "DATA" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP

  return value:  Result of SMTP_OK: based on codes in popforward.h.
                 
 *********************************************************************/
void SMTP_rset(int socket)
{
  SockPrintf(socket,"RSET\n");
}



/*********************************************************************
  function:      SMTP_check
  description:   Returns the status of the smtp connection
                 8/13/96, HSH
  arguments:     
    socket       TCP/IP socket for connection to SMTP

  return value:  based on codes in popforward.h.
                 Do the dirty work of seeing what the status is..
 *********************************************************************/
static int SMTP_check(int socket,char *argbuf)
{
  int  ok;  
  char buf[SMTPBUFSIZE];
  
  if (SMTP_Gets(socket, buf, sizeof(buf))  > 0) {
    if (argbuf)
      strcpy(argbuf,buf);
    if (buf[0] == '1' || buf[0] == '2' || buf[0] == '3')
      ok = SM_OK;
    else 
      ok = SM_ERROR;
  }
  else
    ok= SM_UNRECOVERABLE;
  return (ok);
}

/*********************************************************************
  function:      SMTP_ok
  description:   Returns the statsus of the smtp connection
                 7/31/96, HSH
  arguments:     
    socket       TCP/IP socket for connection to SMTP

  return value:  based on codes in popforward.h.
                 
  NOTE:  As of 7/31/96 Initial implementation, we're just returning 
  a dummy value of SM_OK. Eventually, we should really implement this.
 *********************************************************************/
int SMTP_ok(int socket,char *argbuf)
{
  int  ok;  
  char buf[SMTPBUFSIZE];

  /* I can tell that the SMTP server connection is ok if I can read a
     status message that starts with "1xx" ,"2xx" or "3xx".
     Therefore, it can't be ok if there's no data waiting to be read
     
     Tried to deal with this with a call to SockDataWaiting, but 
     it failed badly.

    */

  ok = SMTP_check(socket,argbuf);
  if (ok == SM_ERROR) /* if we got an error, */
    {
      SMTP_rset(socket);
      ok = SMTP_check(socket,argbuf);  /* how does it look now ? */
      if (ok == SM_OK)  
	ok = SM_ERROR;                /* It's just a simple error, for*/
				      /*	 the current message  */
      else
	ok = SM_UNRECOVERABLE;       /* if It still says error, we're */
                                     /* in bad shape                  */ 
    }
  return ok;
}

/*********************************************************************
  function:      SMTP_Gets
  description:   Gets  a line from the SMTP connection
                 7/31/96, HSH
  arguments:     
    socket       TCP/IP socket for connection to SMTP

  return value:  number of bytes read.
                 
 *********************************************************************/
int SMTP_Gets(int socket,char *buf,int sz)
{
  return read(socket,buf,sz);
}


/*********************************************************************
  function:      POP3_readSMTP
  description:   Read the message content as described in RFC 1225.
  arguments:     
    number       message number.
    socket       ... to which the server is connected.
    mboxfd       open file descriptor to which the retrieved message will
                 be written. 
    options      added 7/30/96, HSH send in the whole options package...
    server:      originating pop server.  7/30/96, HSH

  This procedure is the SMTP version of the original POP3_readmsg that 
  is found in the original popforward.  8/2/96, HSH
  return value:  zero if success else PS_* return code.
  calls:         SockGets.
  globals:       reads outlevel. 
 *********************************************************************/

int POP3_readSMTP(int number,int socket,int mboxfd,struct optrec *options,
		  char *server)
{ 
  char buf [MSGBUFSIZE]; 
  char smtpbuf[SMTPBUFSIZE];
  char *bufp;
  char fromBuf[MSGBUFSIZE];
  char *summaryHeaders[3];
  int  sumLines =0;
  int needFrom;
  int inheaders;
  int lines,sizeticker;
  int n;
  time_t now;

  char *from = NULL;
  int  replFlag = 0;
  

  /* HSH 8/19/96, Archive file  */

  int archive = 0;

  int msgnum = 0;


  /* This keeps the retrieved message count for display purposes */
  int ok=0;

  /* set up for status message if outlevel allows it */
  /* Get this into log file as well. */


  ok = POP3_parseHeaders(number,socket,&from,&replFlag);
  if (ok != 0)
    {
      if (from) free(from);
      return(PS_IOERR);
    }
      
  ok = POP3_sendGet(number,options,socket);
  if (ok != 0)
    {
      if (from) free(from);
      return(PS_IOERR);
    }

  /* 8/19/96 HSH open the archive file.. */

  if ((archive =archGetFile(options,&msgnum)) <= 0)
    {
     if (from) free(from);
      return(PS_IOERR);
    }
  
  /* reads the message content from the server */
  inheaders = 1;
  lines = 0;
  sizeticker = MSGBUFSIZE;
  while (1) {
    if (SockGets(socket,buf,sizeof(buf)) < 0)
      {
	if (from) free(from);
	return(PS_SOCKET);
      }
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
    

 
   if (lines == 0) {
      if (strlen(bufp) >= strlen("From ")) 
	needFrom = strncasecmp(bufp,"From ",strlen("From "));
      else
        needFrom = 1;

      if ((ok = SMTP_sendMessageHeaders(mboxfd,options,from)) != SM_OK)
	  goto smtperr;
   
      if (needFrom) {
        now = time(NULL);
        sprintf(fromBuf,"From POPmail %s",ctime(&now));
        if ((ok =SendData(mboxfd,fromBuf,0)) != SM_OK) 
	  goto smtperr;
      }
   }

   n = write(archive,bufp,strlen(bufp));

    /* write this line to the file */
    if ((ok =SendData(mboxfd,bufp,0)) != SM_OK)
      {
	/* Abort the message, so we'll be clear.. */
	SendData(mboxfd,BINMAIL_TERM,0); 
	goto smtperr;
      }


    sizeticker -= strlen(bufp);
    lines++;
  }

  if ((ok =SendData(mboxfd,BINMAIL_TERM,0)) !=SM_OK) 
    goto smtperr;


  /* finish up display output */
  
  if (from) free(from);
  if (archive != 0) close(archive);
  return(0);

smtperr:
    if (archive != 0) close(archive);
    SMTP_rset(mboxfd);
    if (from) free(from);
    return(ok);
}

/******************************************************************
  function:	POP3_parseHeaders
  description:	Read the headers of the mail message, in order to grab the 
                "From" and "reply to" fields, to be used for proper
		mail processing.
  arguments:
      number    message number
      socket    TCP socket for POP connection
      from      character pointer to hold value of message "FROM" field
      replFlag  indicates whether or not we've seen a reply flag.

  ret. value:	non-zero on success, else zero.
  globals:	SockGets POP3_OK.
  calls:	reads outlevel.
 *****************************************************************/
int POP3_parseHeaders(number,socket,from,replFlag)
int number;
int socket;
char **from;
int  *replFlag;
{

  int ok;
  char buf[MSGBUFSIZE];
  char *bufp;
  int  len;

  ok = POP3_sendTOP(number,0,socket);
  if (ok != 0)
      return(ok);
  
  ok = -1; /* we're not ok until we find "FROM: " */
  /* read lines in until we're done.. */
  while (1)
    {

      if (SockGets(socket,buf,sizeof(buf)) < 0)
	{
	  return(PS_SOCKET);
	}
      bufp = buf;

      if (*bufp == '.') {
	bufp++;
	if (*bufp == 0)
	  break;  /* end of message */
      }

      len = strlen(buf);
      if (len < strlen(HEADER_FROM)) /* since From header is shorter than reply-to, it */
	continue;                    /* can't be either type. */

      /* if it starts with "FROM: ", grab from */
      if (strncasecmp(buf,HEADER_FROM,strlen(HEADER_FROM)) == 0)
	{
	  bufp = buf + strlen(HEADER_FROM);
	  *from = strdup(bufp); 
	  ok =0;
	}
      if (strncasecmp(buf,HEADER_REPLY,strlen(HEADER_REPLY)) == 0)
	  *replFlag = 1;
    }

  return(ok);
}


/******************************************************************
  function:	SMTP_sendMessageHeaders
  description:	Send the headers for the smtp message along to the mailbox..
  arguments:
      number    message number
      socket    TCP socket for POP connection
      from      character pointer to hold value of message "FROM" field
      replFlag  indicates whether or not we've seen a reply flag.

  ret. value:	non-zero on success, else zero.
  globals:	SockGets POP3_OK.
  calls:	reads outlevel.
 *****************************************************************/
int SMTP_sendMessageHeaders(int mboxfd,struct optrec *options,char *from)
{
  char smtpbuf[SMTPBUFSIZE];
  char fromBuf[MSGBUFSIZE];

  int ok;

  /* 7/30/96, HSH add stuff to print out the SMTP commands. */
  ok  = SMTP_ok(mboxfd,smtpbuf);
  if (ok != SM_OK)
    {
      return ok;
    }
  /* mail is from whoever the headers said it was from */
  sprintf(fromBuf,"MAIL FROM: %s\r\n",from);
  if ((ok = SendData(mboxfd,fromBuf,1)) != SM_OK) 
    return ok;
  
/* Now here, add something for the receipt field.  7/30/96,
   HSH */
  sprintf(fromBuf,"RCPT TO: %s@%s\r\n",options->forwarduser,
	  options->forwardhost);
  if ((ok=SendData(mboxfd,fromBuf,1)) != SM_OK) 
    return ok;

  sprintf(fromBuf,"DATA\r\n");
  ok =SendData(mboxfd,fromBuf,1);
  return ok;
   
}

/******************************************************************
  function:	SendData
  description:	Write to socket or file, as appropriate for destination
  arguments:
    f		socket or file descriptor
    buf         buffer to write
    dest        options destination.
    check       1 if we should check for SMTP_ok, 0 if not...
                ignored if DEST is not TO_SMTP
  7/30/96 HSH added

  ret. value:	0 if ok, otherwise, non-zero..
  globals:	none.
  calls:	SockWrite
 *****************************************************************/

static int SendData(int f,char *buf,int check)
{ 
  int res;
  char smtpbuf[SMTPBUFSIZE];
  int len = strlen(buf);

  res = SockWrite(f,buf,len);
  if (check != 0)
    {
          res  = SMTP_ok(f,smtpbuf);
    }
   return res;
}


