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
#include <unistd.h>
#include <string.h>
#include "fetchmail.h"
#include "socket.h"
#include "smtp.h"

struct opt
{
    char *name;
    int value;
};

static struct opt extensions[] =
{
    {"8BITMIME", ESMTP_8BITMIME},
    {(char *)NULL, 0},
};

int smtp_response;	/* numeric value of SMTP response code */

int SMTP_helo(FILE *sockfp,char *host)
/* send a "HELO" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"HELO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> HELO %s", host);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_ehlo(FILE *sockfp, char *host, int *opt)
/* send a "EHLO" message to the SMTP listener, return extension status bits */
{
  int ok;
  char buf[SMTPBUFSIZE], *ip;
  struct opt *hp;

  SockPrintf(sockfp,"EHLO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> EHLO %s", host);
  
  *opt = 0;
  while ((ip = SockGets(buf, sizeof(buf)-1, sockfp)))
  {
      int  n = strlen(ip);

      if (buf[strlen(buf)-1] == '\n')
	  buf[strlen(buf)-1] = '\0';
      if (buf[strlen(buf)-1] == '\r')
	  buf[strlen(buf)-1] = '\r';
      if (n < 4)
	  return SM_ERROR;
      buf[n] = '\0';
      if (outlevel == O_VERBOSE)
	  error(0, 0, "SMTP< %s", buf);
      for (hp = extensions; hp->name; hp++)
	  if (!strncasecmp(hp->name, buf+4, strlen(hp->name)))
	      *opt |= hp->value;
      smtp_response = atoi(buf);
      if ((buf[0] == '1' || buf[0] == '2' || buf[0] == '3') && buf[3] == ' ')
	  return SM_OK;
      else if (buf[3] != '-')
	  return SM_ERROR;
  }
  return SM_UNRECOVERABLE;
}

int SMTP_from(FILE *sockfp, char *from, char *opts)
/* send a "MAIL FROM:" message to the SMTP listener */
{
  int ok;
  struct opt *hp;
  char buf[MSGBUFSIZE];

  sprintf(buf, "MAIL FROM:<%s>", from);
  if (opts)
      strcat(buf, opts);
  SockPrintf(sockfp,"%s\r\n", buf);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> %s", buf);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_rcpt(FILE *sockfp, char *to)
/* send a "RCPT TO:" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"RCPT TO:<%s>\r\n", to);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> RCPT TO:<%s>", to);
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_data(FILE *sockfp)
/* send a "DATA" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"DATA\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> DATA");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_quit(FILE *sockfp)
/* send a "QUIT" message to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,"QUIT\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> QUIT");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_eom(FILE *sockfp)
/* send a message data terminator to the SMTP listener */
{
  int ok;

  SockPrintf(sockfp,".\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP>. (EOM)");
  ok = SMTP_ok(sockfp);
  return ok;
}

int SMTP_ok(FILE *sockfp)
/* returns status of SMTP connection */
{
    char buf[SMTPBUFSIZE], *ip;
  
    while ((ip = SockGets(buf, sizeof(buf)-1, sockfp)))
    {
	int  n = strlen(ip);

	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\r';
	if (n < 4)
	    return SM_ERROR;
	buf[n] = '\0';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "SMTP< %s", buf);
	smtp_response = atoi(buf);
	if ((buf[0] == '1' || buf[0] == '2' || buf[0] == '3') && buf[3] == ' ')
	    return SM_OK;
	else if (buf[3] != '-')
	    return SM_ERROR;
    }
    return SM_UNRECOVERABLE;
}

/* smtp.c ends here */
