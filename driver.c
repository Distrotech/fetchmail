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
#include  <ctype.h>
#include  <string.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
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

int batchlimit;		/* how often to tear down the delivery connection */
int batchcount;		/* count of messages sent in current batch */

static const struct method *protocol;
static jmp_buf	restart;

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static char *shroud;	/* string to shroud in debug output, if  non-NULL */
static int mytimeout;	/* value of nonreponse timeout */

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

static void vtalarm(int timeleft)
/* reset the nonresponse-timeout */
{
    struct itimerval ntimeout;

    ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
    ntimeout.it_value.tv_sec  = timeleft;
    ntimeout.it_value.tv_usec = 0;
    setitimer(ITIMER_VIRTUAL, &ntimeout, (struct itimerval *)NULL);
}

static void vtalarm_handler (int signal)
/* handle server-timeout SIGVTALARM signal */
{
    longjmp(restart, 1);
}

#ifdef HAVE_RES_SEARCH
#define MX_RETRIES	3

static int is_host_alias(const char *name, struct query *ctl)
/* determine whether name is a DNS alias of the hostname */
{
    struct hostent	*he;
    struct mxentry	*mxp, *mxrecords;
    int			i;

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
     * We know DNS service was up at the beginning of this poll cycle.
     * If it's down, our nameserver has crashed.  We don't want to try
     * delivering the current message or anything else from this
     * mailbox until it's back up.
     */
    else if ((he = gethostbyname(name)) != (struct hostent *)NULL)
	return(strcmp(ctl->canonical_name, he->h_name) == 0);
    else
	switch (h_errno)
	{
	case HOST_NOT_FOUND:	/* specified host is unknown */
	case NO_ADDRESS:	/* valid, but does not have an IP address */
	    break;

	case NO_RECOVERY:	/* non-recoverable name server error */
	case TRY_AGAIN:		/* temporary error on authoritative server */
	default:
	    if (outlevel != O_SILENT)
		putchar('\n');	/* terminate the progress message */
	    fprintf(stderr,
		"fetchmail: nameserver failure while looking for `%s' during poll of %s.\n",
		name, ctl->servername);
	    ctl->errcount++;
	    longjmp(restart, 2);	/* try again next poll cycle */
	    break;
	}

    /*
     * We're only here if DNS was OK but the gethostbyname() failed
     * with a HOST_NOT_FOUND or NO_ADDRESS error.
     * Search for a name match on MX records pointing to the server.
     */
    h_errno = 0;
    if ((mxrecords = getmxrecords(name)) == (struct mxentry *)NULL)
	switch (h_errno)
	{
	case HOST_NOT_FOUND:	/* specified host is unknown */
	    return(FALSE);

	case NO_ADDRESS:	/* valid, but does not have an IP address */
	    for (mxp = mxrecords; mxp->name; mxp++)
		if (strcmp(name, mxp->name) == 0)
		    return(TRUE);
	    break;

	case NO_RECOVERY:	/* non-recoverable name server error */
	case TRY_AGAIN:		/* temporary error on authoritative server */
	default:
	    fprintf(stderr,
		"fetchmail: nameserver failure while looking for `%s' during poll of %s.\n",
		name, ctl->servername);
	    ctl->errcount++;
	    longjmp(restart, 2);	/* try again next poll cycle */
	    break;
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
		char	*atsign;

		if ((atsign = strchr(cp, '@')))
		{
		    /*
		     * Address has an @. Check to see if the right-hand part
		     * is an alias or MX equivalent of the mailserver.  If it's
		     * not, skip this name.  If it is, we'll keep going and try
		     * to find a mapping to a client name.
		     */
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
#endif /* HAVE_RES_SEARCH */

static FILE *smtp_open(struct query *ctl)
/* try to open a socket to the appropriate SMTP server for this query */ 
{
    ctl = ctl->leader; /* go to the SMTP leader for this query */

    /* maybe it's time to close the socket in order to force delivery */
    if (batchlimit && ctl->smtp_sockfp && batchcount++ == batchlimit)
    {
	fclose(ctl->smtp_sockfp);
	ctl->smtp_sockfp = (FILE *)NULL;
	batchcount = 0;
    }

    /* if no socket to this host is already set up, try to open one */
    if (ctl->smtp_sockfp == (FILE *)NULL)
    {
	if ((ctl->smtp_sockfp = Socket(ctl->smtphost, SMTP_PORT)) == (FILE *)NULL)
	    return((FILE *)NULL);
	else if (SMTP_ok(ctl->smtp_sockfp, NULL) != SM_OK
		 || SMTP_helo(ctl->smtp_sockfp, ctl->servername) != SM_OK)
	{
	    fclose(ctl->smtp_sockfp);
	    ctl->smtp_sockfp = (FILE *)NULL;
	}
    }

    return(ctl->smtp_sockfp);
}

static int gen_readmsg (sockfp, len, delimited, ctl)
/* read message content and ship to SMTP or MDA */
FILE *sockfp;		/* to which the server is connected */
long len;		/* length of message */
int delimited;		/* does the protocol use a message delimiter? */
struct query *ctl;	/* query control record */
{
    char buf [MSGBUFSIZE+1]; 
    char *bufp, *headers, *fromhdr, *tohdr, *cchdr, *bcchdr;
    int n, oldlen, mboxfd;
    int inheaders,lines,sizeticker;
    FILE *sinkfp;

    /* read the message content from the server */
    inheaders = 1;
    headers = fromhdr = tohdr = cchdr = bcchdr = NULL;
    lines = 0;
    sizeticker = 0;
    oldlen = 0;
    while (delimited || len > 0)
    {
	if ((n = SockGets(buf,sizeof(buf),sockfp)) < 0)
	    return(PS_SOCKET);
	vtalarm(ctl->timeout);

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
		headers = xmalloc(oldlen + 1);
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
		 * (We know this is safe because SocketGets stripped
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

	    if (!strncasecmp("From:", bufp, 5))
		fromhdr = bufp;
	    else if (!fromhdr && !strncasecmp("Resent-From:", bufp, 12))
		fromhdr = bufp;
	    else if (!fromhdr && !strncasecmp("Apparently-From:", bufp, 16))
		fromhdr = bufp;
	    else if (!strncasecmp("To:", bufp, 3))
		tohdr = bufp;
	    else if (!strncasecmp("Apparently-To:", bufp, 14))
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
	    int			good_addresses, bad_addresses;
#ifdef HAVE_RES_SEARCH
	    int			no_local_matches = FALSE;
#endif /* HAVE_RES_SEARCH */

	    /* cons up a list of local recipients */
	    xmit_names = (struct idlist *)NULL;
	    bad_addresses = good_addresses = 0;
#ifdef HAVE_RES_SEARCH
	    /* is this a multidrop box? */
	    if (MULTIDROP(ctl))
	    {
		/* compute the local address list */
		find_server_names(tohdr,  ctl, &xmit_names);
		find_server_names(cchdr,  ctl, &xmit_names);
		find_server_names(bcchdr, ctl, &xmit_names);
		if (!xmit_names)
		{
		    no_local_matches = TRUE;
		    save_uid(&xmit_names, -1, user);
		    if (outlevel == O_VERBOSE)
			fprintf(stderr, 
				"fetchmail: no local matches, forwarding to %s\n",
				user);
		}
	    }
	    else	/* it's a single-drop box, use first localname */
#endif /* HAVE_RES_SEARCH */
		save_uid(&xmit_names, -1, ctl->localnames->id);

	    /* time to address the message */
	    if (ctl->mda[0])	/* we have a declared MDA */
	    {
		int	i, nlocals = 0;
		char	**sargv, **sp;

		/*
		 * We go through this in order to be able to handle very
		 * long lists of users and (re)implement %s.
		 */
		for (idp = xmit_names; idp; idp = idp->next)
		    nlocals++;
		sp = sargv = (char **)alloca(sizeof(char **) * ctl->mda_argcount+nlocals+2);
		for (i = 0; i < ctl->mda_argcount; i++)
		    if (strcmp("%s", ctl->mda_argv[i]))
			*sp++ = ctl->mda_argv[i];
		    else
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
		{
		    fprintf(stderr, "fetchmail: MDA open failed\n");
		    return(PS_IOERR);
		}
	    }
	    else
	    {
		char	*ap;

		if (ctl->mda[0] == '\0'	&& ((sinkfp = smtp_open(ctl)) < 0))
		{
		    free_uid_list(&xmit_names);
		    fprintf(stderr, "fetchmail: SMTP connect failed\n");
		    return(PS_SMTP);
		}

		if (!fromhdr)
		{
		    fprintf(stderr, "fetchmail: I see no From header\n");
		    return(PS_SMTP);
		}

		if (SMTP_from(sinkfp, ap = nxtaddr(fromhdr)) != SM_OK)
		{
		    fprintf(stderr, "fetchmail: SMTP listener doesn't like the From address `%s'\n", ap);
		    return(PS_SMTP);
		}

		for (idp = xmit_names; idp; idp = idp->next)
		    if (SMTP_rcpt(sinkfp, idp->id) == SM_OK)
			good_addresses++;
		    else
		    {
			bad_addresses++;
			idp->val.num = 0;
			fprintf(stderr, 
				"fetchmail: SMTP listener doesn't like recipient address `%s'\n", idp->id);
		    }
		if (!good_addresses && SMTP_rcpt(sinkfp, user) != SM_OK)
		{
		    fprintf(stderr, 
			    "fetchmail: can't even send to calling user!\n");
		    return(PS_SMTP);
		}

		SMTP_data(sinkfp);
		if (outlevel == O_VERBOSE)
		    fputs("SMTP> ", stderr);
	    }

	    /* change continuation markers back to regular newlines */
	    for (cp = headers; cp < headers + oldlen; cp++)
		if (*cp == '\r')
		    *cp = '\n';

	    /* replace all LFs with CR-LF before sending to the SMTP server */
	    if (!ctl->mda[0])
	    {
		char *newheaders = xmalloc(1 + oldlen * 2);

		oldlen = strcrlf(newheaders, headers, oldlen);
		free(headers);
		headers = newheaders;
	    }

	    /* write all the headers */
	    if (ctl->mda[0])
		n = write(mboxfd,headers,oldlen);
	    else
		n = SockWrite(headers, oldlen, sinkfp);

	    if (n < 0)
	    {
		free(headers);
		headers = NULL;
		perror("fetchmail: writing RFC822 headers");
		return(PS_IOERR);
	    }
	    else if (outlevel == O_VERBOSE)
		fputs("#", stderr);
	    free(headers);
	    headers = NULL;

	    /* write error notifications */
#ifdef HAVE_RES_SEARCH
	    if (no_local_matches || bad_addresses)
#else
	    if (bad_addresses)
#endif /* HAVE_RES_SEARCH */
	    {
		int	errlen = 0;
		char	errhd[USERNAMELEN + POPBUFSIZE], *errmsg;

		errmsg = errhd;
		(void) strcpy(errhd, "X-Fetchmail-Warning: ");
#ifdef HAVE_RES_SEARCH
		if (no_local_matches)
		{
		    strcat(errhd, "no recipient addresses matched declared local names");
		    if (bad_addresses)
			strcat(errhd, "; ");
		}
#endif /* HAVE_RES_SEARCH */

		if (bad_addresses)
		{
		    strcat(errhd, "SMTP listener rejected local recipient addresses: ");
		    errlen = strlen(errhd);
		    for (idp = xmit_names; idp; idp = idp->next)
			if (!idp->val.num)
			    errlen += strlen(idp->id) + 2;

		    errmsg = alloca(errlen+3);
		    (void) strcpy(errmsg, errhd);
		    for (idp = xmit_names; idp; idp = idp->next)
			if (!idp->val.num)
			{
			    strcat(errmsg, idp->id);
			    if (idp->next)
				strcat(errmsg, ", ");
			}
		}

		strcat(errmsg, "\n");

		if (ctl->mda[0])
		    write(mboxfd, errmsg, strlen(errmsg));
		else
		    SockWrite(errmsg, strlen(errmsg), sinkfp);
	    }

	    free_uid_list(&xmit_names);
	}

	/* SMTP byte-stuffing */
	if (*bufp == '.' && ctl->mda[0] == 0)
	    SockWrite(".", 1, sinkfp);

	/* replace all LFs with CR-LF  in the line */
	if (!ctl->mda[0])
	{
	    char *newbufp = xmalloc(1 + strlen(bufp) * 2);

	    strcrlf(newbufp, bufp, strlen(bufp));
	    bufp = newbufp;
	}

	/* ship out the text line */
	if (ctl->mda[0])
	    n = write(mboxfd,bufp,strlen(bufp));
	else
	    n = SockWrite(bufp, strlen(bufp), sinkfp);

	if (!ctl->mda[0])
	    free(bufp);
	if (n < 0)
	{
	    perror("fetchmail: writing message text");
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
	if (SMTP_eom(sinkfp) != SM_OK)
	{
	    fputs("fetchmail: SMTP listener refused delivery\n", stderr);
	    return(PS_SMTP);
	}
    }

    return(0);
}

#ifdef KERBEROS_V4
int
kerberos_auth (int socket, canonical) 
/* authenticate to the server host using Kerberos V4 */
int socket;		/* socket to server host */
const char *canonical;	/* server name */
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
struct query *ctl;		/* parsed options with merged-in defaults */
const struct method *proto;	/* protocol method table */
{
    int ok, js;
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

    /* set up the server-nonresponse timeout */
    sigsave = signal(SIGVTALRM, vtalarm_handler);
    vtalarm(mytimeout = ctl->timeout);

    if ((js = setjmp(restart)) == 1)
    {
	fprintf(stderr,
		"fetchmail: timeout after %d seconds waiting for %s.\n",
		ctl->timeout, ctl->servername);
	ok = PS_ERROR;
    }
    else if (js == 2)
    {
	/* error message printed at point of longjmp */
	ok = PS_ERROR;
    }
    else
    {
	char buf [POPBUFSIZE+1];
	int *msgsizes, len, num, count, new, deletions = 0;
	FILE *sockfp;

	/* open a socket to the mail server */
	if ((sockfp = Socket(ctl->servername,
			     ctl->port ? ctl->port : protocol->port)) == NULL)
	{
	    perror("fetchmail, connecting to host");
	    ok = PS_SOCKET;
	    goto closeUp;
	}

#ifdef KERBEROS_V4
	if (ctl->authenticate == A_KERBEROS)
	{
	    ok = (kerberos_auth (fileno(sockfp), ctl->canonical_name));
	    vtalarm(ctl->timeout);
 	    if (ok != 0)
		goto cleanUp;
	}
#endif /* KERBEROS_V4 */

	/* accept greeting message from mail server */
	ok = (protocol->parse_response)(sockfp, buf);
	vtalarm(ctl->timeout);
	if (ok != 0)
	    goto cleanUp;

	/* try to get authorized to fetch mail */
	shroud = ctl->password;
	ok = (protocol->getauth)(sockfp, ctl, buf);
	vtalarm(ctl->timeout);
	shroud = (char *)NULL;
	if (ok == PS_ERROR)
	    ok = PS_AUTHFAIL;
	if (ok != 0)
	    goto cleanUp;

	/* compute number of messages and number of new messages waiting */
	if ((protocol->getrange)(sockfp, ctl, &count, &new) != 0)
	    goto cleanUp;
	vtalarm(ctl->timeout);

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
	{
	    msgsizes = (int *)alloca(sizeof(int) * count);

	    if ((ok = (proto->getsizes)(sockfp, count, msgsizes)) != 0)
		return(PS_ERROR);
	}


	if (check_only)
	{
	    if (new == -1 || ctl->fetchall)
		new = count;
	    ok = ((new > 0) ? PS_SUCCESS : PS_NOMAIL);
	    goto closeUp;
	}
	else if (count > 0)
	{    
	    /*
	     * What forces this code is that in POP3 you can't fetch a
	     * message without having it marked `seen'.
	     *
	     * The result is that if there's any kind of transient error
	     * (DNS lookup failure, or sendmail refusing delivery due to
	     * process-table limits) the message will be marked "seen" on
	     * the server without having been delivered.  This is not a
	     * big problem if fetchmail is running in foreground, because
	     * the user will see a "skipped" message when it next runs and
	     * get clued in.
	     *
	     * But in daemon mode this leads to the message being silently
	     * ignored forever.  This is not acceptable.
	     *
	     * We compensate for this by checking the error count from the 
	     * previous pass and forcing all messages to be considered new
	     * if it's nonzero.
	     */
	    int	force_retrieval = (ctl->errcount > 0);

	    ctl->errcount = 0;

	    /* read, forward, and delete messages */
	    for (num = 1; num <= count; num++)
	    {
		int	toolarge = msgsizes && (msgsizes[num-1] > ctl->limit);
		int	fetch_it = ctl->fetchall ||
		    (!toolarge && (force_retrieval || !(protocol->is_old && (protocol->is_old)(sockfp,ctl,num)));

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
		    (protocol->fetch)(sockfp, num, &len);
		    vtalarm(ctl->timeout);

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

		    /* read the message and ship it to the output sink */
		    ok = gen_readmsg(sockfp,
				     len, 
				     protocol->delimited,
				     ctl);
		    vtalarm(ctl->timeout);
		    if (ok != 0)
			goto cleanUp;

		    /* tell the server we got it OK and resynchronize */
		    if (protocol->trail)
			(protocol->trail)(sockfp, ctl, num);
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
			fprintf(stderr, " flushed\n");
		    ok = (protocol->delete)(sockfp, ctl, num);
		    vtalarm(ctl->timeout);
		    if (ok != 0)
			goto cleanUp;
		    delete_uid(&ctl->newsaved, num);
		}
		else if (outlevel > O_SILENT) 
		    fprintf(stderr, " not flushed\n");
	    }

	    /* remove all messages flagged for deletion */
	    if (protocol->expunge_cmd && deletions > 0)
	    {
		ok = gen_transact(sockfp, protocol->expunge_cmd);
		if (ok != 0)
		    goto cleanUp;
	    }

	    ok = gen_transact(sockfp, protocol->exit_cmd);
	    if (ok == 0)
		ok = PS_SUCCESS;
	    fclose(sockfp);
	    goto closeUp;
	}
	else {
	    ok = gen_transact(sockfp, protocol->exit_cmd);
	    if (ok == 0)
		ok = PS_NOMAIL;
	    fclose(sockfp);
	    goto closeUp;
	}

    cleanUp:
	if (ok != 0 && ok != PS_SOCKET)
	{
	    gen_transact(sockfp, protocol->exit_cmd);
	    fclose(sockfp);
	}
    }

    switch (ok)
    {
    case PS_SOCKET:
	fputs("fetchmail: socket", stderr);
	break;
    case PS_AUTHFAIL:
	fputs("fetchmail: authorization", stderr);
	break;
    case PS_SYNTAX:
	fputs("fetchmail: missing or bad RFC822 header", stderr);
	break;
    case PS_IOERR:
	fputs("fetchmail: MDA", stderr);
	break;
    case PS_ERROR:
	fputs("fetchmail: client/server synchronization", stderr);
	break;
    case PS_PROTOCOL:
	fputs("fetchmail: client/server protocol", stderr);
	break;
    case PS_SMTP:
	fputs("fetchmail: SMTP transaction", stderr);
	break;
    case PS_UNDEFINED:
	fputs("fetchmail: undefined", stderr);
	break;
    }
    if (ok==PS_SOCKET || ok==PS_AUTHFAIL || ok==PS_SYNTAX || ok==PS_IOERR
		|| ok==PS_ERROR || ok==PS_PROTOCOL || ok==PS_SMTP)
	fprintf(stderr, " error while talking to %s\n", ctl->servername);

closeUp:
    signal(SIGVTALRM, sigsave);
    return(ok);
}

#if defined(HAVE_STDARG_H)
void gen_send(FILE *sockfp, char *fmt, ... )
/* assemble command in printf(3) style and send to the server */
{
#else
void gen_send(sockfp, fmt, va_alist)
/* assemble command in printf(3) style and send to the server */
FILE *sockfp;		/* socket to which server is connected */
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

    strcat(buf, "\r\n");
    SockWrite(buf, strlen(buf), sockfp);

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && (cp = strstr(buf, shroud)))
	    memset(cp, '*', strlen(shroud));
	fprintf(stderr,"> %s", buf);
    }
}

#if defined(HAVE_STDARG_H)
int gen_transact(FILE *sockfp, char *fmt, ... )
/* assemble command in printf(3) style, send to server, accept a response */
{
#else
int gen_transact(sockfp, fmt, va_alist)
/* assemble command in printf(3) style, send to server, accept a response */
FILE *sockfp;		/* socket to which server is connected */
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

  strcat(buf, "\r\n");
  SockWrite(buf, strlen(buf), sockfp);
  if (outlevel == O_VERBOSE)
  {
      char *cp;

      if (shroud && (cp = strstr(buf, shroud)))
	  memset(cp, '*', strlen(shroud));
      fprintf(stderr,"> %s", buf);
  }

  /* we presume this does its own response echoing */
  ok = (protocol->parse_response)(sockfp, buf);
  vtalarm(mytimeout);

  return(ok);
}

/* driver.c ends here */
