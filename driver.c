/* Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       driver.c
  project:      fetchmail
  programmer:   Eric S. Raymond
  description:  Generic driver for mail fetch method protocols

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
#include  <malloc.h>

#include  "socket.h"
#include  "fetchmail.h"
#include  "smtp.h"

static struct method *protocol;

#define	SMTP_PORT	25	/* standard SMTP service port */

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

#ifdef HAVE_PROTOTYPES
static int gen_readmsg (int socket, int mboxfd, long len, int delimited,
       char *user, char *host, int topipe, int rewrite);
#endif /* HAVE_PROTOTYPES */

/*********************************************************************
  function:      do_protocol
  description:   retrieve messages from the specified mail server
                 using a given set of methods

  arguments:     
    queryctl     fully-specified options (i.e. parsed, defaults invoked,
                 etc).
    proto        protocol method pointer

  return value:  exit code from the set of PS_.* constants defined in 
                 fetchmail.h
  calls:
  globals:       reads outlevel.
 *********************************************************************/

int do_protocol(queryctl, proto)
struct hostrec *queryctl;
struct method *proto;
{
    int ok, len;
    int mboxfd;
    char buf [POPBUFSIZE+1], host[HOSTLEN+1];
    int socket;
    int first,number,count;

    tagnum = 0;
    protocol = proto;

    /* open the output sink, locking it if it is a folder */
    if (queryctl->output == TO_FOLDER || queryctl->output == TO_STDOUT) {
	if ((mboxfd = openuserfolder(queryctl)) < 0) 
	    return(PS_IOERR);
    } else if (queryctl->output == TO_SMTP) {
	if ((mboxfd = Socket(queryctl->smtphost, SMTP_PORT)) < 0) 
	    return(PS_SOCKET);

	/* eat the greeting message */
	if (SMTP_ok(mboxfd, NULL) != SM_OK) {
	    close(mboxfd);
	    mboxfd = 0;
	    return(PS_SMTP);
	}
    
	/* make it look like mail is coming from the server */
	if (SMTP_helo(mboxfd,queryctl->servername) != SM_OK) {
	    close(mboxfd);
	    mboxfd = 0;
	    return(PS_SMTP);
	}
    }

    /* open a socket to the mail server */
    if ((socket = Socket(queryctl->servername,
			 queryctl->port ? queryctl->port : protocol->port))<0)
    {
	perror("do_protocol: socket");
	ok = PS_SOCKET;
	goto closeUp;
    }

    /* accept greeting message from mail server */
    ok = (protocol->parse_response)(buf, socket);
    if (ok != 0) {
	if (ok != PS_SOCKET)
	    gen_transact(socket, protocol->exit_cmd);
	close(socket);
	goto closeUp;
    }

    /* try to get authorized to fetch mail */
    ok = (protocol->getauth)(socket, queryctl, buf);
    if (ok == PS_ERROR)
	ok = PS_AUTHFAIL;
    if (ok != 0)
	goto cleanUp;

    /* compute count and first */
    if ((*protocol->getrange)(socket, queryctl, &count, &first) != 0)
	goto cleanUp;

    /* show them how many messages we'll be downloading */
    if (outlevel > O_SILENT && outlevel < O_VERBOSE)
	if (count == 0)
	    fprintf(stderr, "No mail from %s\n", queryctl->servername);
	else if (first > 1) 
	    fprintf(stderr,
		    "%d message%s from %s, %d new messages.\n", 
		    count, count > 1 ? "s" : "", 
		    queryctl->servername, count - first + 1);
	else
	    fprintf(stderr,
		    "%d %smessage%s from %s.\n",
		    count, ok ? "" : "new ", 
		    count > 1 ? "s" : "", 
		    queryctl->servername);

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
		    if (protocol->delimited)
			fprintf(stderr,"fetching message %d (delimited)\n",number);
		    else
			fprintf(stderr,"fetching message %d (%d bytes)\n",number,len);
		ok = gen_readmsg(socket,mboxfd,len,protocol->delimited,
				 queryctl->localname,
				 queryctl->servername,
				 queryctl->output, 
				 !queryctl->norewrite);
		if (protocol->trail)
		    (*protocol->trail)(socket, queryctl, number);
		if (ok != 0)
		    goto cleanUp;
	    }

	    /* maybe we delete this message now? */
	    if (protocol->delete_cmd)
	    {
		if ((number < first && queryctl->flush) || !queryctl->keep) {
		    if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
			fprintf(stderr,"flushing message %d\n", number);
		    else
			;
		    ok = gen_transact(socket, protocol->delete_cmd, number);
		    if (ok != 0)
			goto cleanUp;
		}
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
	    ok = gen_transact(socket, protocol->expunge_cmd);
	    if (ok != 0)
		goto cleanUp;
        }

	ok = gen_transact(socket, protocol->exit_cmd);
	if (ok == 0)
	    ok = PS_SUCCESS;
	close(socket);
	goto closeUp;
    }
    else {
	ok = gen_transact(socket, protocol->exit_cmd);
	if (ok == 0)
	    ok = PS_NOMAIL;
	close(socket);
	goto closeUp;
    }

cleanUp:
    if (ok != 0 && ok != PS_SOCKET)
	gen_transact(socket, protocol->exit_cmd);

closeUp:
    if (queryctl->output == TO_FOLDER)
    {
	if (closeuserfolder(mboxfd) < 0 && ok == 0)
	    ok = PS_IOERR;
    }
    else if (queryctl->output == TO_SMTP && mboxfd > 0) {
	SMTP_quit(mboxfd);
	close(mboxfd);
    }

    if (ok == PS_IOERR || ok == PS_SOCKET) 
	perror("do_protocol: cleanUp");

    return(ok);
}

/*********************************************************************
  function:      gen_send
  description:   Assemble command in print style and send to the server

  arguments:     
    socket       socket to which the server is connected.
    fmt          printf-style format

  return value:  none.
  calls:         SockPuts.
  globals:       reads outlevel.
 *********************************************************************/

void gen_send(socket, fmt, va_alist)
int socket;
const char *fmt;
va_dcl {

  char buf [POPBUFSIZE+1];
  va_list ap;

  if (protocol->tagged)
      (void) sprintf(buf, "%s ", GENSYM);
  else
      buf[0] = '\0';

  va_start(ap);
  vsprintf(buf + strlen(buf), fmt, ap);
  va_end(ap);

  SockPuts(socket, buf);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s\n", buf);
}

/*********************************************************************
  function:      gen_transact
  description:   Assemble command in print style and send to the server.
                 then accept a protocol-dependent response.

  arguments:     
    socket       socket to which the server is connected.
    fmt          printf-style format

  return value:  none.
  calls:         SockPuts, imap_ok.
  globals:       reads outlevel.
 *********************************************************************/

int gen_transact(socket, fmt, va_alist)
int socket;
const char *fmt;
va_dcl {

  int ok;
  char buf [POPBUFSIZE+1];
  va_list ap;

  if (protocol->tagged)
      (void) sprintf(buf, "%s ", GENSYM);
  else
      buf[0] = '\0';

  va_start(ap);
  vsprintf(buf + strlen(buf), fmt, ap);
  va_end(ap);

  SockPuts(socket, buf);

  if (outlevel == O_VERBOSE)
    fprintf(stderr,"> %s\n", buf);

  ok = (protocol->parse_response)(buf,socket);
  if (ok != 0 && outlevel > O_SILENT && outlevel <= O_VERBOSE)
    fprintf(stderr,"%s\n",buf);

  return(ok);
}

/*********************************************************************
  function:      
  description:   hack message headers so replies will work properly

  arguments:
    after        where to put the hacked header
    before       header to hack
    host         name of the pop header

  return value:  none.
  calls:         none.
 *********************************************************************/

static void reply_hack(buf, host)
/* hack local mail IDs -- code by Eric S. Raymond 20 Jun 1996 */
char *buf;
const char *host;
{
    const char *from;
    int state = 0;
    char mycopy[POPBUFSIZE+1];

    if (strncmp("From: ", buf, 6)
	&& strncmp("To: ", buf, 4)
	&& strncmp("Reply-", buf, 6)
	&& strncmp("Cc: ", buf, 4)
	&& strncmp("Bcc: ", buf, 5)) {
	return;
    }

    strcpy(mycopy, buf);
    for (from = mycopy; *from; from++)
    {
	switch (state)
	{
	case 0:   /* before header colon */
	    if (*from == ':')
		state = 1;
	    break;

	case 1:   /* we've seen the colon, we're looking for addresses */
	    if (*from == '"')
		state = 2;
	    else if (*from == '(')
		state = 3;    
	    else if (*from == '<' || isalnum(*from))
		state = 4;
	    break;

	case 2:   /* we're in a quoted human name, copy and ignore */
	    if (*from == '"')
		state = 1;
	    break;

	case 3:   /* we're in a parenthesized human name, copy and ignore */
	    if (*from == ')')
		state = 1;
	    break;

	case 4:   /* the real work gets done here */
	    /*
	     * We're in something that might be an address part,
	     * either a bare unquoted/unparenthesized text or text
	     * enclosed in <> as per RFC822.
	     */
	    /* if the address part contains an @, don't mess with it */
	    if (*from == '@')
		state = 5;

	    /* If the address token is not properly terminated, ignore it. */
	    else if (*from == ' ' || *from == '\t')
		state = 1;

	    /*
	     * On proper termination with no @, insert hostname.
	     * Case '>' catches <>-enclosed mail IDs.  Case ',' catches
	     * comma-separated bare IDs.  Cases \r and \n catch the case
	     * of a single ID alone on the line.
	     */
	    else if (strchr(">,\r\n", *from))
	    {
		strcpy(buf, "@");
		strcat(buf, host);
		buf += strlen(buf);
		state = 1;
	    }

	    /* everything else, including alphanumerics, just passes through */
	    break;

	case 5:   /* we're in a remote mail ID, no need to append hostname */
	    if (*from == '>' || *from == ',' || isspace(*from))
		state = 1;
	    break;
	}

	/* all characters from the old buffer get copied to the new one */
	*buf++ = *from;
    }
    *buf++ = '\0';
}

/*********************************************************************
  function:      nxtaddr
  description:   Parse addresses in succession out of a specified RFC822
                 header.  Note 1: RFC822 escaping with \ is *not* handled.
                 Note 2: it is important that this routine not stop on \r,
                 since we use \r as a marker for RFC822 continuations below.
  arguments:     
    hdr          header line to be parsed, NUL to continue in previous hdr

  return value:  next address, or NUL if there is no next address
  calls:         none
 *********************************************************************/

static char *nxtaddr(hdr)
char *hdr;
{
    static char	*hp, *tp, address[POPBUFSIZE+1];
    static	state;

    if (hdr)
    {
	hp = hdr;
	state = 0;
    }

    for (; *hp; hp++)
    {
	switch (state)
	{
	case 0:   /* before header colon */
	    if (*hp == '\n')
		return(NULL);
	    else if (*hp == ':')
	    {
		state = 1;
		tp = address;
	    }
	    break;

	case 1:   /* we've seen the colon, now grab the address */
	    if ((*hp == '\n') || (*hp == ','))  /* end of address list */
	    {
	        *tp++ = '\0';
		return(address);
	    }
	    else if (*hp == '"') /* quoted string */
	    {
	        state = 2;
		*tp++ = *hp;
	    }
	    else if (*hp == '(') /* address comment -- ignore */
		state = 3;    
	    else if (*hp == '<') /* begin <address> */
	    {
		state = 4;
		tp = address;
	    }
	    else if (isspace(*hp)) /* ignore space */
	        state = 1;
	    else   /* just take it */
	    {
		state = 1;
		*tp++ = *hp;
	    }
	    break;

	case 2:   /* we're in a quoted string, copy verbatim */
	    if (*hp == '\n')
		return(NULL);
	    if (*hp != '"')
	        *tp++ = *hp;
	    else if (*hp == '"')
	    {
	        *tp++ = *hp;
		state = 1;
	    }
	    break;

	case 3:   /* we're in a parenthesized comment, ignore */
	    if (*hp == '\n')
		return(NULL);
	    else if (*hp == ')')
		state = 1;
	    break;

	case 4:   /* possible <>-enclosed address */
	    if (*hp == '>') /* end of address */
	    {
		*tp++ = '\0';
		state = 1;
		return(address);
	    }
	    else if (*hp == '<')  /* nested <> */
	        tp = address;
	    else if (*hp == '"') /* quoted address */
	    {
	        *tp++ = *hp;
		state = 5;
	    }
	    else  /* just copy address */
		*tp++ = *hp;
	    break;

	case 5:   /* we're in a quoted address, copy verbatim */
	    if (*hp == '\n')  /* mismatched quotes */
		return(NULL);
	    if (*hp != '"')  /* just copy it if it isn't a quote */
	        *tp++ = *hp;
	    else if (*hp == '"')  /* end of quoted string */
	    {
	        *tp++ = *hp;
		state = 4;
	    }
	    break;
	}
    }

    return(NULL);
}

/*********************************************************************
  function:      gen_readmsg
  description:   Read the message content 

 as described in RFC 1225.
  arguments:     
    socket       ... to which the server is connected.
    mboxfd       open file descriptor to which the retrieved message will
                 be written.
    len          length of text 
    popuser      name of the POP user 
    pophost      name of the POP host 
    output       output mode

  return value:  zero if success else PS_* return code.
  calls:         SockGets.
  globals:       reads outlevel. 
 *********************************************************************/

int gen_readmsg (socket,mboxfd,len,delimited,popuser,pophost,output,rewrite)
int socket;
int mboxfd;
long len;
int delimited;
char *popuser;
char *pophost;
int output;
int rewrite;
{ 
    char buf [MSGBUFSIZE+1]; 
    char fromBuf[MSGBUFSIZE+1];
    char *bufp, *headers, *unixfrom, *fromhdr, *tohdr, *cchdr, *bcchdr;
    int n, oldlen;
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
	    fputs("\n",stderr);
    }

    /* read the message content from the server */
    inheaders = 1;
    headers = unixfrom = fromhdr = tohdr = cchdr = bcchdr = NULL;
    lines = 0;
    sizeticker = 0;
    while (delimited || len > 0) {
	if ((n = SockGets(socket,buf,sizeof(buf))) < 0)
	    return(PS_SOCKET);
	len -= n;
	bufp = buf;
	if (buf[0] == '\0' || buf[0] == '\r' || buf[0] == '\n')
	    inheaders = 0;
	if (*bufp == '.') {
	    bufp++;
	    if (delimited && *bufp == 0)
		break;  /* end of message */
	}
	strcat(bufp, output == TO_SMTP && !inheaders ? "\r\n" : "\n");
     
	if (inheaders)
        {
	    if (rewrite)
		reply_hack(bufp, pophost);

	    if (!lines)
	    {
		oldlen = strlen(bufp);
		headers = malloc(oldlen + 1);
		if (headers == NULL)
		    return(PS_IOERR);
		(void) strcpy(headers, bufp);
		bufp = headers;
	    }
	    else
	    {
		int	newlen;

		/*
		 * We deal with RFC822 continuation lines here.
		 * Replace previous '\n' with '\r' so nxtaddr 
		 * and reply-hack will be able to see past it.
		 * We'll undo this before writing the header.
		 */
		if (isspace(bufp[0]))
		    headers[oldlen-1] = '\r';

		newlen = oldlen + strlen(bufp);
		headers = realloc(headers, newlen + 1);
		if (headers == NULL)
		    return(PS_IOERR);
		strcpy(headers + oldlen, bufp);
		bufp = headers + oldlen;
		oldlen = newlen;
	    }

	    if (!strncmp(bufp,"From ",5))
		unixfrom = bufp;
	    else if (!strncmp("From: ", bufp, 6))
		fromhdr = bufp;
	    else if (!strncmp("To: ", bufp, 4))
		tohdr = bufp;
	    else if (!strncmp("Cc: ", bufp, 4))
		cchdr = bufp;
	    else if (!strncmp("Bcc: ", bufp, 5))
		bcchdr = bufp;

	    goto skipwrite;
	}
	else if (headers)
	{
	    char	*cp;

	    switch (output)
	    {
	    case TO_SMTP:
		if (SMTP_from(mboxfd, nxtaddr(fromhdr)) != SM_OK)
		    return(PS_SMTP);
#ifdef SMTP_RESEND
		/*
		 * This is what we'd do if fetchmail were a real MDA
		 * a la sendmail -- crack all the destination headers
		 * and send to every address we can reach via SMTP.
		 */
		if ((cp = nxtaddr(tohdr)) != (char *)NULL)
		    do {
			if (SMTP_rcpt(mboxfd, cp) == SM_UNRECOVERABLE)
			    return(PS_SMTP);
		    } while
			(cp = nxtaddr(NULL));
		if ((cp = nxtaddr(cchdr)) != (char *)NULL)
		    do {
			if (SMTP_rcpt(mboxfd, cp) == SM_UNRECOVERABLE)
			    return(PS_SMTP);
		    } while
			(cp = nxtaddr(NULL));
		if ((cp = nxtaddr(bcchdr)) != (char *)NULL)
		    do {
			if (SMTP_rcpt(mboxfd, cp) == SM_UNRECOVERABLE)
			    return(PS_SMTP);
		    } while
			(cp = nxtaddr(NULL));
#else
		/*
		 * Since we're really only fetching mail for one user
		 * per host query, we can be simpler
		 */
		if (SMTP_rcpt(mboxfd, popuser) == SM_UNRECOVERABLE)
		    return(PS_SMTP);
#endif /* SMTP_RESEND */
		SMTP_data(mboxfd);
		if (outlevel == O_VERBOSE)
		    fputs("SMTP> ", stderr);
		break;

	    case TO_FOLDER:
	    case TO_STDOUT:
		if (unixfrom)
		    (void) strcpy(fromBuf, unixfrom);
		else
		{
		    now = time(NULL);
		    if (fromhdr && (cp = nxtaddr(fromhdr)))
			sprintf(fromBuf,
				"From %s %s", cp, ctime(&now));
		    else
			sprintf(fromBuf,
				"From POPmail %s",ctime(&now));
		}

		if (write(mboxfd,fromBuf,strlen(fromBuf)) < 0) {
		    perror("gen_readmsg: writing From header");
		    return(PS_IOERR);
		}
		break;

	    case TO_MDA:
		break;
	    }

	    /* change continuation markers back to regular newlines */
	    for (cp = headers; cp < headers +  oldlen; cp++)
		if (*cp == '\r')
		    *cp = '\n';

	    if (write(mboxfd,headers,oldlen) < 0)
	    {
		free(headers);
		headers = NULL;
		perror("gen_readmsg: writing RFC822 headers");
		return(PS_IOERR);
	    }
	    else if (outlevel == O_VERBOSE)
		fputs("#", stderr);
	    free(headers);
	    headers = NULL;
	}

	/* write this line to the file */
	if (write(mboxfd,bufp,strlen(bufp)) < 0)
	{
	    perror("gen_readmsg: writing message text");
	    return(PS_IOERR);
	}
	else if (outlevel == O_VERBOSE)
	    fputc('*', stderr);

    skipwrite:;

	sizeticker += strlen(bufp);
	while (sizeticker >= MSGBUFSIZE)
	{
	    if (outlevel > O_SILENT && outlevel < O_VERBOSE && mboxfd != 1)
		fputc('.',stderr);
	    sizeticker -= MSGBUFSIZE;
	}
	lines++;
    }

    if (outlevel == O_VERBOSE)
	fputc('\n', stderr);

    /* write message terminator, if any */
    switch (output)
    {
    case TO_SMTP:
	if (SMTP_eom(mboxfd) != SM_OK)
	    return(PS_SMTP);
	break;

    case TO_FOLDER:
    case TO_STDOUT:
	/* The server may not write the extra newline required by the Unix
	   mail folder format, so we write one here just in case */
	if (write(mboxfd,"\n",1) < 0) {
	    perror("gen_readmsg: writing terminator");
	    return(PS_IOERR);
	}
	break;

    case TO_MDA:
	/* The mail delivery agent may require a terminator.  Write it if
	   it has been defined */
#ifdef BINMAIL_TERM
	if (write(mboxfd,BINMAIL_TERM,strlen(BINMAIL_TERM)) < 0) {
	    perror("gen_readmsg: writing terminator");
	    return(PS_IOERR);
	}
#endif /* BINMAIL_TERM */
	break;
    }

    /* finish up display output */
    if (outlevel == O_VERBOSE)
	fprintf(stderr,"(%d lines of message content)\n",lines);
    else if (outlevel > O_SILENT && mboxfd != 1) 
	fputs("\n",stderr);
    else
	;
    return(0);
}
