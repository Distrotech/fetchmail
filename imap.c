/* Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       imap.c
  project:      popclient
  programmer:   Eric S. Raymond
  description:  IMAP client code

 ***********************************************************************/

#include  <config.h>
#include  <varargs.h>

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

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int generic_ok (char *buf, int socket);
void generic_send ();
int transact ();
int generic_readmsg (int socket, int mboxfd, int len,
       char *host, int topipe, int rewrite);
#endif

#define TAGLEN	5
static char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static int count, first;

typedef struct
{
    char *name;			/* protocol name */
    int	port;			/* service port */
    int tagged;			/* if true, generate & expect command tags */
    int (*parse_response)();	/* response_parsing function */
    int (*getauth)();		/* authorization fetcher */
    int (*getrange)();		/* get message range to fetch */
    int (*fetch)();		/* fetch a given message */
    int (*trail)();		/* eat trailer of a message */
    char *delete_cmd;		/* delete command */
    char *expunge_cmd;		/* expunge command */
    char *exit_cmd;		/* exit command */
}
method;

/*********************************************************************

 Method declarations for IMAP 

 *********************************************************************/

static int exists, unseen, recent;

int imap_ok (argbuf,socket)
/* parse command response */
char *argbuf;
int socket;
{
  int ok;
  char buf [POPBUFSIZE];
  char *bufp;
  int n;

  do {
    if (SockGets(socket, buf, sizeof(buf)) < 0)
      return(PS_SOCKET);

    if (outlevel == O_VERBOSE)
      fprintf(stderr,"%s\n",buf);

    /* interpret untagged status responses */
    if (strstr(buf, "EXISTS"))
	exists = atoi(buf+2);
    if (strstr(buf, "RECENT"))
	recent = atoi(buf+2);
    if (sscanf(buf + 2, "OK [UNSEEN %d]", &n) == 1)
	unseen = n;

  } while
      (tag[0] != '\0' && strncmp(buf, tag, strlen(tag)));

  if (tag[0] == '\0')
    return(0); 
  else {
    if (strncmp(buf + TAGLEN + 1, "OK", 2) == 0) {
      strcpy(argbuf, buf + TAGLEN);
      return(0);
    }
    else if (strncmp(buf + TAGLEN + 1, "BAD", 2) == 0)
      return(PS_ERROR);
    else
      return(PS_PROTOCOL);
  }
}

int imap_getauth(socket, queryctl)
/* apply for connection authorization */
int socket;
struct hostrec *queryctl;
{
    /* try to get authorized */
    return(transact(socket,
		  "LOGIN %s %s",
		  queryctl->remotename, queryctl->password));
}

static imap_getrange(socket, queryctl, countp, firstp)
/* get range of messages to be fetched */
int socket;
struct hostrec *queryctl;
int *countp;
int *firstp;
{
    int ok;

    /* find out how many messages are waiting */
    exists = unseen = recent = -1;
    ok = transact(socket,
		  "SELECT %s",
		  queryctl->remotefolder[0] ? queryctl->remotefolder : "INBOX");
    if (ok != 0)
	return(ok);

    /* compute size of message run */
    *countp = exists;
    if (queryctl->fetchall)
	*firstp = 1;
    else {
	if (exists > 0 && unseen == -1) {
	    fprintf(stderr,
		    "no UNSEEN response; assuming all %d RECENT messages are unseen\n",
		    recent);
	    *firstp = exists - recent + 1;
	} else {
	    *firstp = unseen;
	}
    }

    return(0);
}

static int imap_fetch(socket, number, limit, lenp)
/* request nth message */
int socket;
int number;
int limit;
int *lenp; 
{
    char buf [POPBUFSIZE];
    int	num;

    if (limit) 
	generic_send(socket,
		     "PARTIAL %d RFC822 0 %d",
		     number, limit);
    else 
	generic_send(socket,
		     "FETCH %d RFC822",
		     number);

    /* looking for FETCH response */
    do {
	if (SockGets(socket, buf,sizeof(buf)) < 0)
	    return(PS_SOCKET);
    } while
	    (sscanf(buf+2, "%d FETCH (RFC822 {%d}", &num, lenp) != 2);

    if (num != number)
	return(PS_ERROR);
    else
	return(0);
}

static imap_trail(socket)
/* discard tail of FETCH response */
int socket;
{
    char buf [POPBUFSIZE];

    if (SockGets(socket, buf,sizeof(buf)) < 0)
	return(PS_SOCKET);
}

static method imap =
{
    "IMAP",				/* Internet Message Access Protocol */
    143,				/* standard IMAP3bis/IMAP4 port */
    1,					/* this is a tagged protocol */
    imap_ok,				/* parse command response */
    imap_getauth,			/* get authorization */
    imap_getrange,			/* query range of messages */
    imap_fetch,				/* request given message */
    imap_trail,				/* eat message trailer */
    "STORE %d +FLAGS (\\Deleted)",	/* set IMAP delete flag */
    "EXPUNGE",				/* the IMAP expunge command */
    "LOGOUT",				/* the IMAP exit command */
};

static method *protocol;

/*********************************************************************
  function:      doIMAP
  description:   retrieve messages from the specified mail server
                 using IMAP Version 2bis or Version 4.

  arguments:     
    queryctl     fully-specified options (i.e. parsed, defaults invoked,
                 etc).

  return value:  exit code from the set of PS_.* constants defined in 
                 popclient.h
  calls:
  globals:       reads outlevel.
 *********************************************************************/

int doIMAP (queryctl)
struct hostrec *queryctl;
{
    protocol = &imap;
    return(do_protocol(queryctl));
}

/*********************************************************************

   Everything below here is generic to all protocols.

 *********************************************************************/

int do_protocol(queryctl)
struct hostrec *queryctl;
{
    int ok, len;
    int mboxfd;
    char buf [POPBUFSIZE];
    int socket;
    int first,number,count;

    tagnum = 0;

    /* open stdout or the mailbox, locking it if it is a folder */
    if (queryctl->output == TO_FOLDER || queryctl->output == TO_STDOUT) 
	if ((mboxfd = openuserfolder(queryctl)) < 0) 
	    return(PS_IOERR);
    
    /* open the socket */
    if ((socket = Socket(queryctl->servername,protocol->port)) < 0) {
	perror("do_protocol: socket");
	ok = PS_SOCKET;
	goto closeUp;
    }

    /* accept greeting message from IMAP server */
    ok = imap_ok(buf,socket);
    if (ok != 0) {
	if (ok != PS_SOCKET)
	    transact(socket, protocol->exit_cmd);
	close(socket);
	goto closeUp;
    }

    /* print the greeting */
    if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
	fprintf(stderr,"%s greeting: %s\n", protocol->name, buf);

    /* try to get authorized to fetch mail */
    ok = (protocol->getauth)(socket, queryctl);
    if (ok == PS_ERROR)
	ok = PS_AUTHFAIL;
    if (ok != 0)
	goto cleanUp;

    /* compute count and first */
    if ((*protocol->getrange)(socket, queryctl, &count, &first) != 0)
	goto cleanUp;

    /* show them how many messages we'll be downloading */
    if (outlevel > O_SILENT && outlevel < O_VERBOSE)
	if (first > 1) 
	    fprintf(stderr,"%d messages in folder, %d new messages.\n", 
		    count, count - first + 1);
	else
	    fprintf(stderr,"%d %smessages in folder.\n", count, ok ? "" : "new ");

    if (count > 0) { 
	for (number = queryctl->flush ? 1 : first;  number<=count; number++) {

	    char *cp;

	    /* open the mail pipe if we're using an MDA */
	    if (queryctl->output == TO_MDA
		&& (queryctl->fetchall || number >= first)) {
		ok = (mboxfd = openmailpipe(queryctl)) < 0 ? -1 : 0;
		if (ok != 0)
		    goto cleanUp;
	    }
           
	    if (queryctl->flush && number < first && !queryctl->fetchall) 
		ok = 0;  /* no command to send here, will delete message below */
	    else
	    {
		(*protocol->fetch)(socket, number, linelimit, &len);
		if (outlevel == O_VERBOSE)
		    fprintf(stderr,"fetching message %d (%d bytes)\n",number,len);
		ok = generic_readmsg(socket,mboxfd,len,
				  queryctl->servername,
				  queryctl->output == TO_MDA, 
				  queryctl->rewrite);
		if (protocol->trail)
		    (*protocol->trail)(socket);
		if (ok != 0)
		    goto cleanUp;
	    }

	    /* maybe we delete this message now? */
	    if ((number < first && queryctl->flush) || !queryctl->keep) {
		if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
		    fprintf(stderr,"flushing message %d\n", number);
		else
		    ;
		ok = transact(socket, protocol->delete_cmd, number);
		if (ok != 0)
		    goto cleanUp;
	    }

	    /* close the mail pipe, we'll reopen before next message */
	    if (queryctl->output == TO_MDA
		&& (queryctl->fetchall || number >= first)) {
		ok = closemailpipe(mboxfd);
		if (ok != 0)
		    goto cleanUp;
	    }
	}

	/* remove all messages flagged for deletion */
        if (!queryctl->keep && protocol->expunge_cmd)
	{
	    ok = transact(socket, protocol->expunge_cmd);
	    if (ok != 0)
		goto cleanUp;
        }

	ok = transact(socket, protocol->exit_cmd);
	if (ok == 0)
	    ok = PS_SUCCESS;
	close(socket);
	goto closeUp;
    }
    else {
	ok = transact(socket, protocol->exit_cmd);
	if (ok == 0)
	    ok = PS_NOMAIL;
	close(socket);
	goto closeUp;
    }

cleanUp:
    if (ok != 0 && ok != PS_SOCKET)
	transact(socket, protocol->exit_cmd);

closeUp:
    if (queryctl->output == TO_FOLDER)
	if (closeuserfolder(mboxfd) < 0 && ok == 0)
	    ok = PS_IOERR;
    
    if (ok == PS_IOERR || ok == PS_SOCKET) 
	perror("do_protocol: cleanUp");

    return(ok);
}

/*********************************************************************
  function:      generic_send
  description:   Assemble command in print style and send to the server

  arguments:     
    socket       socket to which the server is connected.
    fmt          printf-style format

  return value:  none.
  calls:         SockPuts.
  globals:       reads outlevel.
 *********************************************************************/

void generic_send(socket, fmt, va_alist)
int socket;
const char *fmt;
va_dcl {

  char buf [POPBUFSIZE];
  va_list ap;

  if (protocol->tagged)
      (void) sprintf(buf, "%s ", GENSYM);

  va_start(ap);
  vsprintf(buf + strlen(buf), fmt, ap);
  va_end(ap);

  SockPuts(socket, buf);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s\n", buf);
}

/*********************************************************************
  function:      transact
  description:   Assemble command in print style and send to the server.
                 then accept a protocol-dependent response.

  arguments:     
    socket       socket to which the server is connected.
    fmt          printf-style format

  return value:  none.
  calls:         SockPuts, imap_ok.
  globals:       reads outlevel.
 *********************************************************************/

int transact(socket, fmt, va_alist)
int socket;
const char *fmt;
va_dcl {

  int ok;
  char buf [POPBUFSIZE];
  va_list ap;

  (void) sprintf(buf, "%s ", GENSYM);

  va_start(ap);
  vsprintf(buf + strlen(buf), fmt, ap);
  va_end(ap);

  SockPuts(socket, buf);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s\n", buf);

  ok = (protocol->parse_response)(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel < O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}

/*********************************************************************
  function:      generic_readmsg
  description:   Read the message content 

 as described in RFC 1225.
  arguments:     
    socket       ... to which the server is connected.
    mboxfd       open file descriptor to which the retrieved message will
                 be written.
    len          lrength of text 
    pophost      name of the POP host 
    topipe       true if we're writing to the system mailbox pipe.

  return value:  zero if success else PS_* return code.
  calls:         SockGets.
  globals:       reads outlevel. 
 *********************************************************************/

int generic_readmsg (socket,mboxfd,len,pophost,topipe,rewrite)
int socket;
int mboxfd;
int len;
char *pophost;
int topipe;
int rewrite;
{ 
  char buf [MSGBUFSIZE]; 
  char *bufp;
  char savec;
  char fromBuf[MSGBUFSIZE];
  int n;
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
  while (len > 0) {
    if ((n = SockGets(socket,buf,sizeof(buf))) < 0)
      return(PS_SOCKET);
    len -= n;
    bufp = buf;
    if (buf[0] == '\r' || buf[0] == '\n')
      inheaders = 0;
    if (*bufp == '.') {
      bufp++;
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
          perror("generic_readmsg: write");
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
      perror("generic_readmsg: write");
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
      perror("generic_readmsg: write");
      return(PS_IOERR);
    }
  }
  else {
    /* The mail delivery agent may require a terminator.  Write it if
       it has been defined */
#ifdef BINMAIL_TERM
    if (write(mboxfd,BINMAIL_TERM,strlen(BINMAIL_TERM)) < 0) {
      perror("generic_readmsg: write");
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



