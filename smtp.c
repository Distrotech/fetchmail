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

#include <config.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "fetchmail.h"
#include "smtp.h"

int SMTP_helo(FILE *sockfp,char *host)
/* send a "HELO" message to the SMTP listener */
{
  int ok;

  fprintf(sockfp,"HELO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> HELO %s\n", host);
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

int SMTP_from(FILE *sockfp, char *from)
/* send a "MAIL FROM:" message to the SMTP listener */
{
  int ok;

  fprintf(sockfp,"MAIL FROM:<%s>\r\n", from);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> MAIL FROM:<%s>\n", from);
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

int SMTP_rcpt(FILE *sockfp, char *to)
/* send a "RCPT TO:" message to the SMTP listener */
{
  int ok;

  fprintf(sockfp,"RCPT TO:<%s>\r\n", to);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RCPT TO:<%s>\n", to);
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

int SMTP_data(FILE *sockfp)
/* send a "DATA" message to the SMTP listener */
{
  int ok;

  fprintf(sockfp,"DATA\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> DATA\n");
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

int SMTP_quit(FILE *sockfp)
/* send a "QUIT" message to the SMTP listener */
{
  int ok;

  fprintf(sockfp,"QUIT\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> QUIT\n");
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

int SMTP_eom(FILE *sockfp)
/* send a message data terminator to the SMTP listener */
{
  int ok;

  fprintf(sockfp,".\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP>. (EOM)\n");
  ok = SMTP_ok(sockfp,NULL);
  return ok;
}

void SMTP_rset(FILE *sockfp)
/* send a "RSET" message to the SMTP listener */
{
  fprintf(sockfp,"RSET\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RSET\n");
}

static int SMTP_check(FILE *sockfp,char *argbuf)
/* returns status of SMTP connection */
{
  int  ok;  
  char buf[SMTPBUFSIZE];
  
  if (fgets(buf, sizeof(buf)-1, sockfp) != (char *)NULL) {
    if (outlevel == O_VERBOSE)
    {
	char	*sp, *tp;

	for (tp = sp = buf; *sp; sp++)
	    if (*sp != '\r')
		*tp++ = *sp;
	*tp++ = '\0';
	fprintf(stderr, "SMTP< %s", buf);
    }
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

int SMTP_ok(FILE *sockfp,char *argbuf)
/* accepts SMTP response, returns status of SMTP connection */
{
  int  ok;  

  /* I can tell that the SMTP server connection is ok if I can read a
     status message that starts with "1xx" ,"2xx" or "3xx".
     Therefore, it can't be ok if there's no data waiting to be read
     
     Tried to deal with this with a call to SockDataWaiting, but 
     it failed badly.

    */

  ok = SMTP_check(sockfp,argbuf);
  if (ok == SM_ERROR) /* if we got an error, */
    {
      SMTP_rset(sockfp);
      ok = SMTP_check(sockfp,argbuf);  /* how does it look now ? */
      if (ok == SM_OK)  
	ok = SM_ERROR;                /* It's just a simple error, for*/
				      /*	 the current message  */
      else
	ok = SM_UNRECOVERABLE;       /* if it still says error, we're */
                                     /* in bad shape                  */ 
    }
  return ok;
}

/* smtp.c ends here */
