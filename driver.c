/*
 * driver.c -- generic driver for mail fetch method protocols
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include  <config.h>
#include  <stdio.h>
#include  <setjmp.h>
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

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#include "mx.h"
#endif /* HAVE_GETHOSTBYNAME */

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
static jmp_buf	restart;

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static char *shroud;

static int strcrlf(dst, src, count)
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

static void alarm_handler (int signal)
/* handle server-timeout signal */
{
    longjmp(restart, 1);
}

static void reply_hack(buf, host)
/* hack message headers so replies will work properly */
char *buf;		/* header to be hacked */
const char *host;	/* server hostname */
{
    const char *from;
    int state = 0, tokencount = 0;
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
		state = 3;
	    else if (*from == '(')
		state = 4;    
	    else if (*from == '<' || isalnum(*from))
		state = 5;
	    else if (isspace(*from))
		state = 2;
	    else if (*from == ',')
		tokencount = 0;
	    break;

	case 2:	    /* found a token boundary -- reset without copying */
	    if (*from != ' ' && *from != '\t')
	    {
		tokencount++;
		state = 1;
		--from;
		continue;
	    }

	case 3:   /* we're in a quoted human name, copy and ignore */
	    if (*from == '"')
		state = 1;
	    break;

	case 4:   /* we're in a parenthesized human name, copy and ignore */
	    if (*from == ')')
		state = 1;
	    break;

	case 5:   /* the real work gets done here */
	    /*
	     * We're in something that might be an address part,
	     * either a bare unquoted/unparenthesized text or text
	     * enclosed in <> as per RFC822.
	     */
	    /* if the address part contains an @, don't mess with it */
	    if (*from == '@')
		state = 6;

	    /* If the address token is not properly terminated, ignore it. */
	    else if (*from == ' ' || *from == '\t')
	    {
		const char *cp;

		/*
		 * The only lookahead case.  If we're looking at space or tab,
		 * we might be looking at a local name immediately followed
		 * by a human name.
		 */
		for (cp = from; isspace(*cp); cp++)
		    continue;
		if (*cp == '(')
		{
		    strcpy(buf, "@");
		    strcat(buf, host);
		    buf += strlen(buf);
		    state = 1;
		}
	    }

	    /*
	     * On proper termination with no @, insert hostname.
	     * Case '>' catches <>-enclosed mail IDs.  Case ',' catches
	     * comma-separated bare IDs.
	     */
	    else if (strchr(">,", *from))
	    {
		strcpy(buf, "@");
		strcat(buf, host);
		buf += strlen(buf);
		state = 1;
	    }

	    /* a single local name alone on the line */
	    else if (*from == '\n' && tokencount == 0)
	    {
		strcpy(buf, "@");
		strcat(buf, host);
		buf += strlen(buf);
		state = 2;
	    }

	    /* everything else, including alphanumerics, just passes through */
	    break;

	case 6:   /* we're in a remote mail ID, no need to append hostname */
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
	    if (*hp == '\n')	/* end of address list */
	    {
	        *tp++ = '\0';
		state = 6;
		return(address);
	    }
	    else if (*hp == ',')  /* end of address */
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

	case 6:
	    return(NULL);
	    break;
	}
    }

    return(NULL);
}

#ifdef HAVE_GETHOSTBYNAME
#define MX_RETRIES	3

static int is_host_alias(name, ctl)
/* determine whether name is a DNS alias of the hostname */
const char *name;
struct query	*ctl;
{
    struct hostent	*he;
    int			i, n;

    /*
     * The first two checks are optimizations that will catch a good
     * many cases.  First, check against the hostname the user specified.
     * Odds are good this will either be the mailserver's FQDN or a
     * suffix of it with the mailserver's domain's default host name
     * omitted.  Next, check against the mailserver's FQDN, in case
     * it's not the same as the declared hostname.
     *
     * Either of these on a mail address is definitive.  Only if the
     * name doesn't match either is it time to call the bind library.
     * If this happens odds are good we're looking at an MX name.
     */
    if (strcmp(name, ctl->servername) == 0)
	return(TRUE);
    else if (strcmp(name, ctl->canonical_name) == 0)
	return(TRUE);

    /*
     * We treat DNS lookup failure as a negative on the theory that
     * the mailserver's DNS server is `nearby' and should be able
     * to respond quickly and reliably.  Ergo if we get failure,
     * the name isn't a mailserver alias.
     */
    else if ((he = gethostbyname(name)) && strcmp(ctl->canonical_name, he->h_name) == 0)
	return(TRUE);

    /*
     * Search for a name match on MX records pointing to the server
     * site.  These may live far away, so allow a couple of retries.
     */
    for (i = 0; i < MX_RETRIES; i++)
    {
	struct mxentry *mxrecords, *mxp;
	int j;

	mxrecords = getmxrecords(name);

	if (mxrecords == (struct mxentry *)NULL)
	    if (h_errno == TRY_AGAIN)
	    {
		sleep(1);
		continue;
	    }
	    else
		break;

	for (mxp = mxrecords; mxp->name; mxp++)
	    if (strcmp(name, mxp->name) == 0)
		return(TRUE);
    }

    return(FALSE);
}

void find_server_names(hdr, ctl, xmit_names)
/* parse names out of a RFC822 header into an ID list */
const char *hdr;		/* RFC822 header in question */
struct query *ctl;	/* list of permissible aliases */
struct idlist **xmit_names;	/* list of recipient names parsed out */
{
    if (hdr == (char *)NULL)
	return;
    else
    {
	char	*cp, *lname;

	if ((cp = nxtaddr(hdr)) != (char *)NULL)
	    do {
		char	*atsign = strchr(cp, '@');

		if (atsign)
		    if (ctl->norewrite)
			continue;
		    else
		    {
			if (!is_host_alias(atsign+1, ctl))
			    continue;
			atsign[0] = '\0';
		    }
		lname = idpair_find(&ctl->localnames, cp);
		if (lname != (char *)NULL)
		{
		    if (outlevel == O_VERBOSE)
			fprintf(stderr,
				"fetchmail: mapped %s to local %s\n",
				cp, lname);
		    save_uid(xmit_names, -1, lname);
		}
	    } while
		((cp = nxtaddr((char *)NULL)) != (char *)NULL);
    }
}
#endif /* HAVE_GETHOSTBYNAME */

static int gen_readmsg (socket, mboxfd, len, delimited, ctl)
/* read message content and ship to SMTP or MDA */
int socket;	/* to which the server is connected */
int mboxfd;	/* descriptor to which retrieved message will be written */
long len;	/* length of message */
int delimited;	/* does the protocol use a message delimiter? */
struct query *ctl;	/* query control record */
{ 
    char buf [MSGBUFSIZE+1]; 
    char fromBuf[MSGBUFSIZE+1];
    char *bufp, *headers, *unixfrom, *fromhdr, *tohdr, *cchdr, *bcchdr;
    int n, oldlen;
    int inheaders,lines,sizeticker;
    /* This keeps the retrieved message count for display purposes */
    static int msgnum = 0;  

    /* read the message content from the server */
    inheaders = 1;
    headers = unixfrom = fromhdr = tohdr = cchdr = bcchdr = NULL;
    lines = 0;
    sizeticker = 0;
    while (delimited || len > 0)
    {
	if ((n = SockGets(socket,buf,sizeof(buf))) < 0)
	    return(PS_SOCKET);

	/* write the message size dots */
	if (n > 0)
	{
	    sizeticker += n;
	    while (sizeticker >= SIZETICKER)
	    {
		if (outlevel > O_SILENT)
		    fputc('.',stderr);
		sizeticker -= SIZETICKER;
	    }
	}
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
	    if (!ctl->norewrite)
		reply_hack(bufp, ctl->servername);

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
	else if (headers)	/* OK, we're at end of headers now */
	{
	    char		*cp;
	    struct idlist 	*idp, *xmit_names;

	    /* cons up a list of local recipients */
	    xmit_names = (struct idlist *)NULL;
#ifdef HAVE_GETHOSTBYNAME
	    /* is this a multidrop box? */
	    if (ctl->localnames != (struct idlist *)NULL
		&& ctl->localnames->next != (struct idlist *)NULL)
	    {
		/* compute the local address list */
		find_server_names(tohdr,  ctl, &xmit_names);
		find_server_names(cchdr,  ctl, &xmit_names);
		find_server_names(bcchdr, ctl, &xmit_names);

		/* if nothing supplied localnames, default appropriately */
		if (!xmit_names)
		    save_uid(&xmit_names, -1, dfltuser);
	    }
	    else	/* it's a single-drop box, use first localname */
#endif /* HAVE_GETHOSTBYNAME */
	    {
		if (ctl->localnames)
		    save_uid(&xmit_names, -1, ctl->localnames->id);
		else
		    save_uid(&xmit_names, -1, dfltuser);
	    }

	    /* time to address the message */
	    if (ctl->mda[0])	/* we have a declared MDA */
	    {
		int	i, nlocals = 0;
		char	**sargv, **sp;

		/*
		 * We go through this in order to be able to handle very
		 * long lists of users.
		 */
		for (idp = xmit_names; idp; idp = idp->next)
		    nlocals++;
		sp = sargv = (char **)alloca(ctl->mda_argcount+nlocals+2);
		for (i = 0; i <= ctl->mda_argcount; i++)
		    *sp++ = ctl->mda_argv[i];
		for (idp = xmit_names; idp; idp = idp->next)
		    *sp++ = idp->id;
		*sp =  (char *)NULL;

#ifdef HAVE_SETEUID
		/*
		 * Arrange to run with user's permissions if we're root.
		 * This will initialize the ownership of any files the
		 * MDA creates properly.  (The seteuid call is available
		 * under all BSDs and Linux)
		 */
		seteuid(ctl->uid);
#endif /* HAVE_SETEUID */

		mboxfd = openmailpipe(sargv);

#ifdef HAVE_SETEUID
		/* this will fail quietly if we didn't start as root */
		seteuid(0);
#endif /* HAVE_SETEUID */

		if (mboxfd < 0)
		    return(PS_IOERR);
	    }
	    else
	    {
		if (SMTP_from(mboxfd, nxtaddr(fromhdr)) != SM_OK)
		    return(PS_SMTP);

		for (idp = xmit_names; idp; idp = idp->next)
		    if (SMTP_rcpt(mboxfd, idp->id) != SM_OK)
			return(PS_SMTP);

		SMTP_data(mboxfd);
		if (outlevel == O_VERBOSE)
		    fputs("SMTP> ", stderr);
	    }
	    free_uid_list(&xmit_names);

	    /* change continuation markers back to regular newlines */
	    for (cp = headers; cp < headers +  oldlen; cp++)
		if (*cp == '\r')
		    *cp = '\n';

	    /* replace all LFs with CR-LF before sending to the SMTP server */
	    if (!ctl->mda[0])
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
	if (*bufp == '.' && ctl->mda[0] == 0)
	    write(mboxfd, ".", 1);

	/* write this line to the file after replacing all LFs with CR-LF */
	if (!ctl->mda[0])
	{
	    char *newbufp = malloc(1 + strlen(bufp) * 2);

	    if (newbufp == NULL)
		return(PS_IOERR);
	    strcrlf(newbufp, bufp, strlen(bufp));
	    bufp = newbufp;
	}
	n = write(mboxfd,bufp,strlen(bufp));
	if (!ctl->mda[0])
	    free(bufp);
	if (n < 0)
	{
	    perror("gen_readmsg: writing message text");
	    return(PS_IOERR);
	}
	else if (outlevel == O_VERBOSE)
	    fputc('*', stderr);

    skipwrite:;
	lines++;
    }

    if (ctl->mda[0])
    {
	/* close the delivery pipe, we'll reopen before next message */
	if (closemailpipe(mboxfd))
	    return(PS_IOERR);
    }
    else
    {
	/* write message terminator */
	if (SMTP_eom(mboxfd) != SM_OK)
	    return(PS_SMTP);
    }

    return(0);
}

#ifdef KERBEROS_V4
int
kerberos_auth (socket, canonical) 
/* authenticate to the server host using Kerberos V4 */
int socket;		/* socket to server host */
char *canonical;	/* server name */
{
    char * host_primary;
    KTEXT ticket;
    MSG_DAT msg_data;
    CREDENTIALS cred;
    Key_schedule schedule;
    int rem;
  
    ticket = ((KTEXT) (malloc (sizeof (KTEXT_ST))));
    rem = (krb_sendauth (0L, socket, ticket, "pop",
			 canonical,
			 ((char *) (krb_realmofhost (canonical))),
			 ((unsigned long) 0),
			 (&msg_data),
			 (&cred),
			 (schedule),
			 ((struct sockaddr_in *) 0),
			 ((struct sockaddr_in *) 0),
			 "KPOPV0.1"));
    free (ticket);
    if (rem != KSUCCESS)
    {
	fprintf (stderr, "fetchmail: kerberos error %s\n", (krb_get_err_text (rem)));
	return (PS_ERROR);
    }
    return (0);
}
#endif /* KERBEROS_V4 */

int do_protocol(ctl, proto)
/* retrieve messages from server using given protocol method table */
struct query *ctl;	/* parsed options with merged-in defaults */
struct method *proto;		/* protocol method table */
{
    int ok, mboxfd = -1;
    void (*sigsave)();

#ifndef KERBEROS_V4
    if (ctl->authenticate == A_KERBEROS)
    {
	fputs("fetchmail: Kerberos support not linked.\n", stderr);
	return(PS_ERROR);
    }
#endif /* KERBEROS_V4 */

    /* lacking methods, there are some options that may fail */
    if (!proto->is_old)
    {
	/* check for unsupported options */
	if (ctl->flush) {
	    fprintf(stderr,
		    "Option --flush is not supported with %s\n",
		    proto->name);
	    return(PS_SYNTAX);
	}
	else if (ctl->fetchall) {
	    fprintf(stderr,
		    "Option --all is not supported with %s\n",
		    proto->name);
	    return(PS_SYNTAX);
	}
    }
    if (!proto->getsizes && ctl->limit)
    {
	fprintf(stderr,
		"Option --limit is not supported with %s\n",
		proto->name);
	return(PS_SYNTAX);
    }

    protocol = proto;
    tagnum = 0;
    tag[0] = '\0';	/* nuke any tag hanging out from previous query */
    ok = 0;

    if (setjmp(restart) == 1)
	fprintf(stderr,
		"fetchmail: timeout after %d seconds waiting for %s.\n",
		ctl->timeout, ctl->servername);
    else
    {
	char buf [POPBUFSIZE+1], host[HOSTLEN+1];
	int *msgsizes, socket, len, num, count, new, deletions = 0;

	/* set up the server-nonresponse timeout */
	sigsave = signal(SIGALRM, alarm_handler);
	alarm(ctl->timeout);

	/* open a socket to the mail server */
	if ((socket = Socket(ctl->servername,
			     ctl->port ? ctl->port : protocol->port))<0)
	{
	    perror("fetchmail, connecting to host");
	    ok = PS_SOCKET;
	    goto closeUp;
	}

#ifdef KERBEROS_V4
	if (ctl->authenticate == A_KERBEROS)
	{
	    ok = (kerberos_auth (socket, ctl->canonical_name));
	    if (ok != 0)
		goto cleanUp;
	}
#endif /* KERBEROS_V4 */

	/* accept greeting message from mail server */
	ok = (protocol->parse_response)(socket, buf);
	if (ok != 0)
	    goto cleanUp;

	/* try to get authorized to fetch mail */
	shroud = ctl->password;
	ok = (protocol->getauth)(socket, ctl, buf);
	shroud = (char *)NULL;
	if (ok == PS_ERROR)
	    ok = PS_AUTHFAIL;
	if (ok != 0)
	    goto cleanUp;

	/* compute number of messages and number of new messages waiting */
	if ((protocol->getrange)(socket, ctl, &count, &new) != 0)
	    goto cleanUp;

	/* show user how many messages we downloaded */
	if (outlevel > O_SILENT)
	    if (count == 0)
		fprintf(stderr, "No mail from %s@%s\n", 
			ctl->remotename,
			ctl->servername);
	    else
	    {
		fprintf(stderr, "%d message%s", count, count > 1 ? "s" : ""); 
		if (new != -1 && (count - new) > 0)
		    fprintf(stderr, " (%d seen)", count-new);
		fprintf(stderr,
			" from %s@%s.\n",
			ctl->remotename,
			ctl->servername);
	    }

	/* we may need to get sizes in order to check message limits */
	msgsizes = (int *)NULL;
	if (!ctl->fetchall && proto->getsizes && ctl->limit)
	    if ((msgsizes = (proto->getsizes)(socket, count)) == (int *)NULL)
		return(PS_ERROR);

	if (check_only)
	{
	    if (new == -1 || ctl->fetchall)
		new = count;
	    ok = ((new > 0) ? PS_SUCCESS : PS_NOMAIL);
	    goto closeUp;
	}
	else if (count > 0)
	{
	    if (ctl->mda[0] == '\0')
		if ((mboxfd = Socket(ctl->smtphost, SMTP_PORT)) < 0
		    || SMTP_ok(mboxfd, NULL) != SM_OK
		    || SMTP_helo(mboxfd, ctl->servername) != SM_OK)
		{
		    ok = PS_SMTP;
		    close(mboxfd);
		    mboxfd = -1;
		    goto cleanUp;
		}
    
	    /* read, forward, and delete messages */
	    for (num = 1; num <= count; num++)
	    {
		int	toolarge = msgsizes && msgsizes[num-1]>ctl->limit;
		int	fetch_it = ctl->fetchall ||
		    (!(protocol->is_old && (protocol->is_old)(socket,ctl,num)) && !toolarge);

		/* we may want to reject this message if it's old */
		if (!fetch_it)
		{
		    if (outlevel > O_SILENT)
		    {
			fprintf(stderr, "skipping message %d", num);
			if (toolarge)
			    fprintf(stderr, " (oversized, %d bytes)", msgsizes[num-1]);
		    }
		}
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

		    /*
		     * If we're forwarding via SMTP, mboxfd is initialized
		     * at this point (it was set at start of retrieval). 
		     * If we're using an MDA it's not set -- gen_readmsg()
		     * may have to parse message headers to know what
		     * delivery addresses should be passed to the MDA
		     */

		    /* read the message and ship it to the output sink */
		    ok = gen_readmsg(socket, mboxfd,
				     len, 
				     protocol->delimited,
				     ctl);

		    /* tell the server we got it OK and resynchronize */
		    if (protocol->trail)
			(protocol->trail)(socket, ctl, num);
		    if (ok != 0)
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
		    && (fetch_it ? !ctl->keep : ctl->flush))
		{
		    deletions++;
		    if (outlevel > O_SILENT) 
			fprintf(stderr, " flushed\n", num);
		    ok = (protocol->delete)(socket, ctl, num);
		    if (ok != 0)
			goto cleanUp;
		}
		else if (outlevel > O_SILENT) 
		{
		    /* nuke it from the unseen-messages list */
		    delete_uid(&ctl->newsaved, num);
		    fprintf(stderr, " not flushed\n", num);
		}
	    }

	    /* remove all messages flagged for deletion */
	    if (protocol->expunge_cmd && deletions > 0)
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
	{
	    gen_transact(socket, protocol->exit_cmd);
	    close(socket);
	}
    }

    alarm(0);
    signal(SIGALRM, sigsave);

closeUp:
    if (mboxfd != -1)
    {
        if (!ctl->mda[0])
	    SMTP_quit(mboxfd);
	close(mboxfd);
    }

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

/* driver.c ends here */
