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

int smtp_response;	/* numeric value of SMTP response code */

int SMTP_helo(FILE *sockfp,char *host)
/* send a "HELO" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"HELO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> HELO %s\n", host);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_from(FILE *sockfp, char *from)
/* send a "MAIL FROM:" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"MAIL FROM:<%s>\r\n", from);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> MAIL FROM:<%s>\n", from);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_rcpt(FILE *sockfp, char *to)
/* send a "RCPT TO:" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"RCPT TO:<%s>\r\n", to);
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> RCPT TO:<%s>\n", to);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_data(FILE *sockfp)
/* send a "DATA" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"DATA\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> DATA\n");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_quit(FILE *sockfp)
/* send a "QUIT" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"QUIT\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP> QUIT\n");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_eom(FILE *sockfp)
/* send a message data terminator to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,".\r\n");
  if (outlevel == O_VERBOSE)
      fprintf(stderr, "SMTP>. (EOM)\n");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_ok(FILE *sockfp)
/* returns status of SMTP connection */
{
    int  n;
    char buf[SMTPBUFSIZE];
  
    while ((n = SockGets(buf, sizeof(buf)-1, sockfp)) > 0)
    {
	if (n < 4)
	    return SM_ERROR;
	buf[n] = '\0';
	if (outlevel == O_VERBOSE)
	    fprintf(stderr, "SMTP< %s\n", buf);
	smtp_response = atoi(buf);
	if ((buf[0] == '1' || buf[0] == '2' || buf[0] == '3') && buf[3] == ' ')
	    return SM_OK;
	else if (buf[3] != '-')
	    return SM_ERROR;
    }
    return SM_UNRECOVERABLE;
}

/* smtp.c ends here */
