/*
 * smtp.c -- code for speaking SMTP to a listener port
 *
 * Concept due to Harry Hochheiser.  Implementation by ESR.  Cleanup and
 * strict RFC821 compliance by Cameron MacPherson.
 *
 * Copyright 1996 Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include <stdio.h>
#include <config.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "socket.h"
#include "fetchmail.h"
#include "smtp.h"

int SMTP_helo(int socket,char *host)
/* send a "HELO" message to the SMTP listener */
{
  int ok;

  SockPrintf(socket,"HELO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> HELO %s\n", host);
  ok = SMTP_ok(socket,NULL);
  return ok;
}

int SMTP_from(int socket, char *from)
/* send a "MAIL FROM:" message to the SMTP listener */
{
  int ok;

  SockPrintf(socket,"MAIL FROM:<%s>\r\n", from);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> MAIL FROM:<%s>\n", from);
  ok = SMTP_ok(socket,NULL);
  return ok;
}

int SMTP_rcpt(int socket, char *to)
/* send a "RCPT TO:" message to the SMTP listener */
{
  int ok;

  SockPrintf(socket,"RCPT TO:<%s>\r\n", to);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RCPT TO:<%s>\n", to);
  ok = SMTP_ok(socket,NULL);
  return ok;
}

int SMTP_data(int socket)
/* send a "DATA" message to the SMTP listener */
{
  int ok;

  SockPrintf(socket,"DATA\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> DATA\n");
  ok = SMTP_ok(socket,NULL);
  return ok;
}

int SMTP_quit(int socket)
/* send a "QUIT" message to the SMTP listener */
{
  int ok;

  SockPrintf(socket,"QUIT\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> QUIT\n");
  ok = SMTP_ok(socket,NULL);
  return ok;
}

int SMTP_eom(int socket)
/* send a message data terminator to the SMTP listener */
{
  int ok;

  SockPrintf(socket,".\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP>. (EOM)\n");
  ok = SMTP_ok(socket,NULL);
  return ok;
}

void SMTP_rset(int socket)
/* send a "RSET" message to the SMTP listener */
{
  SockPrintf(socket,"RSET\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RSET\n");
}

static int SMTP_check(int socket,char *argbuf)
/* returns status of SMTP connection */
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

int SMTP_ok(int socket,char *argbuf)
/* accepts SMTP response, returns status of SMTP connection */
{
  int  ok;  

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

int SMTP_Gets(int socket,char *buf,int sz)
/* gets a line from the SMTP connection, returns bytes read */
{
  return read(socket,buf,sz);
}

/* smtp.c ends here */
