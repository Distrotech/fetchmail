/*
 * smtp.c -- code for speaking SMTP to a listener port
 *
 * Concept due to Harry Hochheiser.  Implementation by ESR.  Cleanup and
 * strict RFC821 compliance by Cameron MacPherson.
 *
 * Copyright 1997 Eric S. Raymond
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
    {"8BITMIME",	ESMTP_8BITMIME},
    {"SIZE",    	ESMTP_SIZE},
    {"ETRN",		ESMTP_ETRN},
    {(char *)NULL, 0},
};

char smtp_response[MSGBUFSIZE];

int SMTP_helo(int sock,char *host)
/* send a "HELO" message to the SMTP listener */
{
  int ok;

  SockPrintf(sock,"HELO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> HELO %s", host);
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_ehlo(int sock, char *host, int *opt)
/* send a "EHLO" message to the SMTP listener, return extension status bits */
{
  struct opt *hp;

  SockPrintf(sock,"EHLO %s\r\n", host);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> EHLO %s", host);
  
  *opt = 0;
  while ((SockRead(sock, smtp_response, sizeof(smtp_response)-1)) != -1)
  {
      int  n = strlen(smtp_response);

      if (smtp_response[strlen(smtp_response)-1] == '\n')
	  smtp_response[strlen(smtp_response)-1] = '\0';
      if (smtp_response[strlen(smtp_response)-1] == '\r')
	  smtp_response[strlen(smtp_response)-1] = '\0';
      if (n < 4)
	  return SM_ERROR;
      smtp_response[n] = '\0';
      if (outlevel == O_VERBOSE)
	  error(0, 0, "SMTP< %s", smtp_response);
      for (hp = extensions; hp->name; hp++)
	  if (!strncasecmp(hp->name, smtp_response+4, strlen(hp->name)))
	      *opt |= hp->value;
      if ((smtp_response[0] == '1' || smtp_response[0] == '2' || smtp_response[0] == '3') && smtp_response[3] == ' ')
	  return SM_OK;
      else if (smtp_response[3] != '-')
	  return SM_ERROR;
  }
  return SM_UNRECOVERABLE;
}

int SMTP_from(int sock, char *from, char *opts)
/* send a "MAIL FROM:" message to the SMTP listener */
{
    int ok;
    char buf[MSGBUFSIZE];

    if (strchr(from, '<'))
	sprintf(buf, "MAIL FROM: %s", from);
    else
	sprintf(buf, "MAIL FROM:<%s>", from);
    if (opts)
	strcat(buf, opts);
    SockPrintf(sock,"%s\r\n", buf);
    if (outlevel == O_VERBOSE)
	error(0, 0, "SMTP> %s", buf);
    ok = SMTP_ok(sock);
    return ok;
}

int SMTP_rcpt(int sock, char *to)
/* send a "RCPT TO:" message to the SMTP listener */
{
  int ok;

  SockPrintf(sock,"RCPT TO:<%s>\r\n", to);
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> RCPT TO:<%s>", to);
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_data(int sock)
/* send a "DATA" message to the SMTP listener */
{
  int ok;

  SockPrintf(sock,"DATA\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> DATA");
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_rset(int sock)
/* send a "RSET" message to the SMTP listener */
{
  int ok;

  SockPrintf(sock,"RSET\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> RSET");
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_quit(int sock)
/* send a "QUIT" message to the SMTP listener */
{
  int ok;

  SockPrintf(sock,"QUIT\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP> QUIT");
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_eom(int sock)
/* send a message data terminator to the SMTP listener */
{
  int ok;

  SockPrintf(sock,".\r\n");
  if (outlevel == O_VERBOSE)
      error(0, 0, "SMTP>. (EOM)");
  ok = SMTP_ok(sock);
  return ok;
}

int SMTP_ok(int sock)
/* returns status of SMTP connection */
{
    while ((SockRead(sock, smtp_response, sizeof(smtp_response)-1)) != -1)
    {
	int  n = strlen(smtp_response);

	if (smtp_response[strlen(smtp_response)-1] == '\n')
	    smtp_response[strlen(smtp_response)-1] = '\0';
	if (smtp_response[strlen(smtp_response)-1] == '\r')
	    smtp_response[strlen(smtp_response)-1] = '\r';
	if (n < 4)
	    return SM_ERROR;
	smtp_response[n] = '\0';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "SMTP< %s", smtp_response);
	if ((smtp_response[0] == '1' || smtp_response[0] == '2' || smtp_response[0] == '3') && smtp_response[3] == ' ')
	    return SM_OK;
	else if (smtp_response[3] != '-')
	    return SM_ERROR;
    }
    return SM_UNRECOVERABLE;
}

/* smtp.c ends here */
