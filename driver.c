/*
 * driver.c -- generic driver for mail fetch method protocols
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#include  <string.h>
#endif
#if defined(HAVE_STDARG_H)
#include  <stdarg.h>
#else
#include  <varargs.h>
#endif
#include  <sys/time.h>
#include  <signal.h>

#ifdef KERBEROS_V4
#include <krb.h>
#include <des.h>
#include <netinet/in.h>		/* must be included before "socket.h".*/
#include <netdb.h>
#endif /* KERBEROS_V4 */
#include  "socket.h"
#include  "fetchmail.h"
#include  "smtp.h"

#define	SMTP_PORT	25	/* standard SMTP service port */

static struct method *protocol;

static int alarmed;	/* a flag to indicate that SIGALRM happened */
static int mytimeout;	/* server-nonresponse timeout for current query */
static char *srvname;	/* current server name for timeout message */

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static char *shroud;

static void reply_hack(buf, host)
/* hack message headers so replies will work properly */
char *buf;		/* header to be hacked */
const char *host;	/* server hostname */
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

static char *nxtaddr(hdr)
/* parse addresses in succession out of a specified RFC822 header */
char *hdr;	/* header line to be parsed, NUL to continue in previous hdr */
{
    static char	*hp, *tp, address[POPBUFSIZE+1];
    static	state;

    /*
     * Note 1: RFC822 escaping with \ is *not* handled.  Note 2: it is
     * important that this routine not stop on \r, since we use \r as
     * a marker for RFC822 continuations below.
     */

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

static int gen_readmsg (socket, mboxfd, len, delimited, queryctl)
/* read message content and ship to SMTP or MDA */
int socket;	/* to which the server is connected */
int mboxfd;	/* descriptor to which retrieved message will be written */
long len;	/* length of message */
int delimited;	/* does the protocol use a message delimiter? */
struct hostrec *queryctl;	/* query control record */
{ 
    char buf [MSGBUFSIZE+1]; 
    char fromBuf[MSGBUFSIZE+1];
    char *bufp, *headers, *unixfrom, *fromhdr, *tohdr, *cchdr, *bcchdr;
    int n, oldlen;
    int inheaders;
    int lines,sizeticker;
    /* This keeps the retrieved message count for display purposes */
    static int msgnum = 0;  

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
	if (delimited && *bufp == '.') {
	    bufp++;
	    if (*bufp == 0)
		break;  /* end of message */
	}
	strcat(bufp, "\n");
     
	if (inheaders)
        {
	    if (!queryctl->norewrite)
		reply_hack(bufp, queryctl->servername);

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
		 * and reply_hack will be able to see past it.
		 * (We know this safe because SocketGets stripped
		 * out all carriage returns in the read loop above
		 * and we haven't reintroduced any since then.)
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
	    else if (!strncasecmp("From:", bufp, 5))
		fromhdr = bufp;
	    else if (!strncasecmp("To:", bufp, 3))
		tohdr = bufp;
	    else if (!strncasecmp("Cc:", bufp, 3))
		cchdr = bufp;
	    else if (!strncasecmp("Bcc:", bufp, 4))
		bcchdr = bufp;

	    goto skipwrite;
	}
	else if (headers)
	{
	    char	*cp;

	    if (!queryctl->mda[0])
	    {
		if (SMTP_from(mboxfd, nxtaddr(fromhdr)) != SM_OK)
		    return(PS_SMTP);
#ifdef SMTP_RESEND
		/*
		 * This is what we'd do if fetchmail were a real MDA
		 * a la sendmail -- crack all the destination headers
		 * and send to every address we can reach via SMTP.
		 */
		if (tohdr && (cp = nxtaddr(tohdr)) != (char *)NULL)
		    do {
			if (SMTP_rcpt(mboxfd, cp) == SM_UNRECOVERABLE)
			    return(PS_SMTP);
		    } while
			(cp = nxtaddr(NULL));
		if (cchdr && (cp = nxtaddr(cchdr)) != (char *)NULL)
		    do {
			if (SMTP_rcpt(mboxfd, cp) == SM_UNRECOVERABLE)
			    return(PS_SMTP);
		    } while
			(cp = nxtaddr(NULL));
		if (bcchdr && (cp = nxtaddr(bcchdr)) != (char *)NULL)
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
		if (SMTP_rcpt(mboxfd, queryctl->localname) == SM_UNRECOVERABLE)
		    return(PS_SMTP);
#endif /* SMTP_RESEND */
		SMTP_data(mboxfd);
		if (outlevel == O_VERBOSE)
		    fputs("SMTP> ", stderr);
	    }

	    /* change continuation markers back to regular newlines */
	    for (cp = headers; cp < headers +  oldlen; cp++)
		if (*cp == '\r')
		    *cp = '\n';

	    /* replace all LFs with CR-LF before sending to the SMTP server */
	    if (!queryctl->mda[0])
	    {
		char *newheaders = malloc(1 + oldlen * 2);

		if (newheaders == NULL)
		    return(PS_IOERR);
		oldlen = strcrlf(newheaders, headers, oldlen);
		free(headers);
		headers = newheaders;
	    }
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

	/* SMTP byte-stuffing */
	if (*bufp == '.' && queryctl->mda[0] == 0)
	    write(mboxfd, ".", 1);

	/* write this line to the file after replacing all LFs with CR-LF */
	if (!queryctl->mda[0])
	{
	    char *newbufp = malloc(1 + strlen(bufp) * 2);

	    if (newbufp == NULL)
		return(PS_IOERR);
	    strcrlf(newbufp, bufp, strlen(bufp));
	    bufp = newbufp;
	}
	n = write(mboxfd,bufp,strlen(bufp));
	if (!queryctl->mda[0])
	    free(bufp);
	if (n < 0)
	{
	    perror("gen_readmsg: writing message text");
	    return(PS_IOERR);
	}
	else if (outlevel == O_VERBOSE)
	    fputc('*', stderr);

    skipwrite:;

	/* write the message size dots */
	sizeticker += strlen(bufp);
	while (sizeticker >= SIZETICKER)
	{
	    if (outlevel > O_SILENT && outlevel < O_VERBOSE)
		fputc('.',stderr);
	    sizeticker -= SIZETICKER;

	    /* reset timeout so we don't choke on very long messages */
	    alarm(queryctl->timeout);
	}
	lines++;
    }

    if (alarmed)
       return (0);
    /* write message terminator */
    if (!queryctl->mda[0])
	if (SMTP_eom(mboxfd) != SM_OK)
	    return(PS_SMTP);
    return(0);
}

#ifdef KERBEROS_V4
int
kerberos_auth (socket, servername) 
/* authenticate to the server host using Kerberos V4 */
int socket;		/* socket to server host */
char *servername;	/* server name */
{
    char * host_primary;
    KTEXT ticket;
    MSG_DAT msg_data;
    CREDENTIALS cred;
    Key_schedule schedule;
    int rem;
  
    /* Get the primary name of the host.  */
    {
	struct hostent * hp = (gethostbyname (servername));
	if (hp == 0)
	{
	    fprintf (stderr, "fetchmail: server %s unknown: n", servername);
	    return (PS_ERROR);
	}
	host_primary = ((char *) (malloc ((strlen (hp -> h_name)) + 1)));
	strcpy (host_primary, (hp -> h_name));
    }
  
    ticket = ((KTEXT) (malloc (sizeof (KTEXT_ST))));
    rem
	= (krb_sendauth (0L, socket, ticket, "pop",
			 host_primary,
			 ((char *) (krb_realmofhost (host_primary))),
			 ((unsigned long) 0),
			 (&msg_data),
			 (&cred),
			 (schedule),
			 ((struct sockaddr_in *) 0),
			 ((struct sockaddr_in *) 0),
			 "KPOPV0.1"));
    free (ticket);
    free (host_primary);
    if (rem != KSUCCESS)
    {
	fprintf (stderr, "fetchmail: kerberos error %s\n", (krb_get_err_text (rem)));
	return (PS_ERROR);
    }
    return (0);
}
#endif /* KERBEROS_V4 */

int do_protocol(queryctl, proto)
/* retrieve messages from server using given protocol method table */
struct hostrec *queryctl;	/* parsed options with merged-in defaults */
struct method *proto;		/* protocol method table */
{
    int ok, len;
    int mboxfd = -1;
    char buf [POPBUFSIZE+1], host[HOSTLEN+1];
    int socket;
    void (*sigsave)();
    int num, count, deletions = 0;

    srvname = queryctl->servername;
    alarmed = 0;
    sigsave = signal(SIGALRM, alarm_handler);
    alarm (mytimeout = queryctl->timeout);

#ifndef KERBEROS_V4
    if (queryctl->authenticate == A_KERBEROS)
    {
	fputs("fetchmail: Kerberos support not linked.\n", stderr);
	return(PS_ERROR);
    }
#endif /* KERBEROS_V4 */

    /* lacking methods, there are some options that may fail */
    if (!proto->is_old)
    {
	/* check for unsupported options */
	if (queryctl->flush) {
	    fprintf(stderr,
		    "Option --flush is not supported with %s\n",
		    proto->name);
            alarm(0);
            signal(SIGALRM, sigsave);
	    return(PS_SYNTAX);
	}
	else if (queryctl->fetchall) {
	    fprintf(stderr,
		    "Option --all is not supported with %s\n",
		    proto->name);
            alarm(0);
            signal(SIGALRM, sigsave);
	    return(PS_SYNTAX);
	}
    }

    tagnum = 0;
    tag[0] = '\0';	/* nuke any tag hanging out from previous query */
    protocol = proto;

    /* open a socket to the mail server */
    if ((socket = Socket(queryctl->servername,
			 queryctl->port ? queryctl->port : protocol->port))<0 
         || alarmed)
    {
	perror("fetchmail, connecting to host");
	ok = PS_SOCKET;
	goto closeUp;
    }

#ifdef KERBEROS_V4
    if (queryctl->authenticate == A_KERBEROS)
    {
	ok = (kerberos_auth (socket, queryctl->servername));
	if (ok != 0)
	    goto cleanUp;
    }
#endif /* KERBEROS_V4 */

    /* accept greeting message from mail server */
    ok = (protocol->parse_response)(socket, buf);
    if (alarmed || ok != 0)
	goto cleanUp;

    /* try to get authorized to fetch mail */
    shroud = queryctl->password;
    ok = (protocol->getauth)(socket, queryctl, buf);
    shroud = (char *)NULL;
    if (alarmed || ok == PS_ERROR)
	ok = PS_AUTHFAIL;
    if (alarmed || ok != 0)
	goto cleanUp;

    /* compute count, and get UID list if possible */
    if ((protocol->getrange)(socket, queryctl, &count) != 0 || alarmed)
	goto cleanUp;

    /* show user how many messages we downloaded */
    if (outlevel > O_SILENT && outlevel < O_VERBOSE)
	if (count == 0)
	    fprintf(stderr, "No mail for %s from %s@%s\n", 
		    queryctl->remotename,
		    queryctl->localname,
		    queryctl->servername);
	else
	    fprintf(stderr,
		    "%d message%s from %s for %s@%s.\n",
		    count, count > 1 ? "s" : "", 
		    queryctl->remotename,
		    queryctl->localname,
		    queryctl->servername);

    if ((count > 0) && (!check_only))
    {
	if (queryctl->mda[0] == '\0')
	    if ((mboxfd = Socket(queryctl->smtphost, SMTP_PORT)) < 0
		|| SMTP_ok(mboxfd, NULL) != SM_OK
		|| SMTP_helo(mboxfd, queryctl->servername) != SM_OK 
                || alarmed)
	    {
		ok = PS_SMTP;
		close(mboxfd);
		mboxfd = -1;
		goto cleanUp;
	    }
    
	/* read, forward, and delete messages */
	for (num = 1; num <= count; num++)
	{
	    int	fetch_it = queryctl->fetchall ||
		!(protocol->is_old && (protocol->is_old)(socket,queryctl,num));

	    /* we may want to reject this message if it's old */
	    if (!fetch_it)
		fprintf(stderr, "skipping message %d ", num);
	    else
	    {
		/* request a message */
		(protocol->fetch)(socket, num, &len);

		if (outlevel > O_SILENT)
		{
		    fprintf(stderr, "reading message %d", num);
		    if (len > 0)
			fprintf(stderr, " (%d bytes)", len);
		    if (outlevel == O_VERBOSE)
			fputc('\n', stderr);
		    else
			fputc(' ', stderr);
		}

		/* open the delivery pipe now if we're using an MDA */
		if (queryctl->mda[0])
		{
#ifdef HAVE_SETEUID
		    /*
		     * Arrange to run with user's permissions if we're root.
		     * This will initialize the ownership of any files the
		     * MDA creates properly.  (The seteuid call is available
		     * under all BSDs and Linux)
		     */
		    seteuid(queryctl->uid);
#endif /* HAVE_SETEUID */
		    mboxfd = openmailpipe(queryctl);
#ifdef HAVE_SETEUID
		    /* this will fail quietly if we didn't start as root */
		    seteuid(0);
#endif /* HAVE_SETEUID */

		    if (mboxfd < 0)
			goto cleanUp;
		}

		/* read the message and ship it to the output sink */
		ok = gen_readmsg(socket, mboxfd,
				 len, 
				 protocol->delimited,
				 queryctl);

		/* close the delivery pipe, we'll reopen before next message */
		if (queryctl->mda[0])
		    if ((ok = closemailpipe(mboxfd)) != 0 || alarmed)
			goto cleanUp;

		/* tell the server we got it OK and resynchronize */
		if (protocol->trail)
		    (protocol->trail)(socket, queryctl, num);
		if (alarmed || ok != 0)
		    goto cleanUp;
	    }

	    /*
	     * At this point in flow of control, either we've bombed
	     * on a protocol error or had delivery refused by the SMTP
	     * server (unlikely -- I've never seen it) or we've seen
	     * `accepted for delivery' and the message is shipped.
	     * It's safe to mark the message seen and delete it on the
	     * server now.
	     */

	    /* maybe we delete this message now? */
	    if (protocol->delete
		&& (fetch_it ? !queryctl->keep : queryctl->flush))
	    {
		deletions++;
		if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
		    fprintf(stderr, " flushed\n", num);
		ok = (protocol->delete)(socket, queryctl, num);
		if (alarmed || ok != 0)
		    goto cleanUp;
	    }
	    else if (outlevel > O_SILENT && outlevel < O_VERBOSE) 
	    {
		/* nuke it from the unseen-messages list */
		delete_uid(&queryctl->newsaved, num);
		fprintf(stderr, " not flushed\n", num);
	    }
	}

	/* remove all messages flagged for deletion */
        if (protocol->expunge_cmd && deletions > 0)
	{
	    ok = gen_transact(socket, protocol->expunge_cmd);
	    if (alarmed || ok != 0)
		goto cleanUp;
        }

	ok = gen_transact(socket, protocol->exit_cmd);
	if (alarmed || ok == 0)
	    ok = PS_SUCCESS;
	close(socket);
	goto closeUp;
    }
    else if (check_only) {
      ok = ((count > 0) ? PS_SUCCESS : PS_NOMAIL);
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
    {
	gen_transact(socket, protocol->exit_cmd);
	close(socket);
    }

closeUp:
    if (mboxfd != -1)
    {
	SMTP_quit(mboxfd);
	close(mboxfd);
    }
    alarm(0);
    signal(SIGALRM, sigsave);
    return(ok);
}

#if defined(HAVE_STDARG_H)
void gen_send(int socket, char *fmt, ... )
/* assemble command in printf(3) style and send to the server */
{
#else
void gen_send(socket, fmt, va_alist)
/* assemble command in printf(3) style and send to the server */
int socket;		/* socket to which server is connected */
const char *fmt;	/* printf-style format */
va_dcl {
#endif

    char buf [POPBUFSIZE+1];
    va_list ap;

    if (protocol->tagged)
	(void) sprintf(buf, "%s ", GENSYM);
    else
	buf[0] = '\0';

#if defined(HAVE_STDARG_H)
    va_start(ap, fmt) ;
#else
    va_start(ap);
#endif
    vsprintf(buf + strlen(buf), fmt, ap);
    va_end(ap);

    SockPuts(socket, buf);

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && (cp = strstr(buf, shroud)))
	    memset(cp, '*', strlen(shroud));
	fprintf(stderr,"> %s\n", buf);
    }
}

#if defined(HAVE_STDARG_H)
int gen_transact(int socket, char *fmt, ... )
/* assemble command in printf(3) style, send to server, accept a response */
{
#else
int gen_transact(socket, fmt, va_alist)
/* assemble command in printf(3) style, send to server, accept a response */
int socket;		/* socket to which server is connected */
const char *fmt;	/* printf-style format */
va_dcl {
#endif

  int ok;
  char buf [POPBUFSIZE+1];
  va_list ap;

  if (protocol->tagged)
      (void) sprintf(buf, "%s ", GENSYM);
  else
      buf[0] = '\0';

#if defined(HAVE_STDARG_H)
  va_start(ap, fmt) ;
#else
  va_start(ap);
#endif
  vsprintf(buf + strlen(buf), fmt, ap);
  va_end(ap);

  SockPuts(socket, buf);
  if (outlevel == O_VERBOSE)
  {
      char *cp;

      if (shroud && (cp = strstr(buf, shroud)))
	  memset(cp, '*', strlen(shroud));
      fprintf(stderr,"> %s\n", buf);
  }

  /* we presume this does its own response echoing */
  ok = (protocol->parse_response)(socket, buf);

  return(ok);
}

int strcrlf(dst, src, count)
/* replace LFs with CR-LF; return length of string with replacements */
char *dst;	/* new string with CR-LFs */
char *src;	/* original string with LFs */
int count;	/* length of src */
{
  int len = count;

  while (count--)
  {
      if (*src == '\n')
      {
	  *dst++ = '\r';
	  len++;
      }
      *dst++ = *src++;
  }
  *dst = '\0';
  return len;
}

void 
alarm_handler (int signal)
/* handle server-timeout signal */
{
    alarmed = 1;
    fprintf(stderr,
	    "fetchmail: timeout after %d seconds waiting for %s.\n",
	    mytimeout, srvname);
}

/* driver.c ends here */
