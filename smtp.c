/* Copyright 1996 Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       smtp.c
  project:      popclient
  programmer:   Harry Hochheiser
  description:  Handling of SMTP connections, and processing of mail 
                 to be forwarded via SMTP connections.

 ***********************************************************************/

#include <stdio.h>
#include <config.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "socket.h"
#include "popclient.h"
#include "smtp.h"

/*********************************************************************
  function:      SMTP_helo
  description:   Send a "HELO" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  Result of SMTP_OK: based on codes in popclient.h.
                 
 *********************************************************************/

int SMTP_helo(int socket,char *host)
{
  int ok;
  char buf[SMTPBUFSIZE+1];

  sprintf(buf,"HELO %s",host);
  SockPuts(socket, buf);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> %s\n", buf);
  ok = SMTP_ok(socket,buf);
  return ok;
}


/*********************************************************************
  function:      SMTP_from
  description:   Send a "MAIL FROM:" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
    from         user name/host of originator

    Note: these args are likely to change, as we get fancier about
    handling the names.

  return value:  Result of SMTP_ok: based on codes in popclient.h.
                 
 *********************************************************************/
int SMTP_from(int socket, char *from)
{
  char buf[SMTPBUFSIZE+1];  /* it's as good as size as any... */
  int ok;
  SockPrintf(socket, "MAIL FROM: %s\n", from);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> MAIL FROM: %s\n", from);
  ok = SMTP_ok(socket,buf);

  return ok;
}


/*********************************************************************
  function:      SMTP_rcpt
  description:   Send a "RCPT TO:" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
    touser:      user name of recipient
    tohost:      host name of recipient

  return value:  Result of SMTP_OK: based on codes in popclient.h.
                 
 *********************************************************************/
int SMTP_rcpt(int socket,char *to)
{
  char buf[SMTPBUFSIZE+1];  /* it's as good as size as any... */
  int ok;

  SockPrintf(socket, "RCPT TO: %s\n", to);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RCPT TO: %s\n", to);
  ok = SMTP_ok(socket,buf);
  
  return ok;
}


/*********************************************************************
  function:      SMTP_data
  description:   Send a "DATA" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP

 *********************************************************************/
int SMTP_data(int socket)
{
  int ok;

  SockPrintf(socket,"DATA\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> DATA\n");
  ok = SMTP_ok(socket, NULL);
  
  return ok;
}

/*********************************************************************
  function:      SMTP_eom
  description:   Send a message data termination to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  Result of SMTP_OK: based on codes in popclient.h.
                 
 *********************************************************************/

int SMTP_eom(int socket)
{
  int ok;

  SockPuts(socket,".");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> (EOM)\n");
  ok = SMTP_ok(socket,NULL);
  return ok;
}

/*********************************************************************
  function:      SMTP_rset
  description:   Send an "RSET" message to the SMTP server.

  arguments:     
    socket       TCP/IP socket for connection to SMTP

 *********************************************************************/
void SMTP_rset(int socket)
{
  SockPrintf(socket,"RSET\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RSET\n");
}

/*********************************************************************
  function:      SMTP_check
  description:   Returns the status of the smtp connection
  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  based on codes in popclient.h.
                 Do the dirty work of seeing what the status is..
 *********************************************************************/
static int SMTP_check(int socket,char *argbuf)
{
  int  ok;  
  char buf[SMTPBUFSIZE];
  
  if ((ok = SMTP_Gets(socket, buf, sizeof(buf)-1)) > 0) {
    buf[ok] = '\0';
    if (outlevel == O_VERBOSE)
	fprintf(stderr, "SMTP< %s", buf);
    if (argbuf)
      strcpy(argbuf,buf);
    if (buf[0] == '1' || buf[0] == '2' || buf[0] == '3')
      ok = SM_OK;
    else 
      ok = SM_ERROR;
  }
  else
    ok = SM_UNRECOVERABLE;
  return (ok);
}

/*********************************************************************
  function:      SMTP_ok
  description:   Returns the statsus of the smtp connection
  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  based on codes in popclient.h.
 *********************************************************************/
int SMTP_ok(int socket,char *argbuf)
{
  int  ok;  
  char buf[SMTPBUFSIZE+1];

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
	ok = SM_UNRECOVERABLE;       /* if it still says error, we're */
                                     /* in bad shape                  */ 
    }
  return ok;
}

/*********************************************************************
  function:      SMTP_Gets
  description:   Gets  a line from the SMTP connection
  arguments:     
    socket       TCP/IP socket for connection to SMTP
  return value:  number of bytes read.
 *********************************************************************/
int SMTP_Gets(int socket,char *buf,int sz)
{
  return read(socket,buf,sz);
}

