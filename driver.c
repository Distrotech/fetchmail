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
#include  <errno.h>
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
#if defined(HAVE_ALLOCA_H)
#include <alloca.h>
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
#include <netinet/in.h>
#include <netdb.h>
#endif /* KERBEROS_V4 */
#include  "socket.h"
#include  "fetchmail.h"
#include  "socket.h"
#include  "smtp.h"

/* BSD portability hack...I know, this is an ugly place to put it */
#if !defined(SIGCHLD) && defined(SIGCLD)
#define SIGCHLD	SIGCLD
#endif

#define	SMTP_PORT	25	/* standard SMTP service port */

extern char *strstr();	/* needed on sysV68 R3V7.1. */

int batchlimit;		/* how often to tear down the delivery connection */
int fetchlimit;		/* how often to tear down the server connection */
int batchcount;		/* count of messages sent in current batch */
int peek_capable;	/* can we peek for better error recovery? */

static const struct method *protocol;
static jmp_buf	restart;

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static char *shroud;	/* string to shroud in debug output, if  non-NULL */
static int mytimeout;	/* value of nonreponse timeout */

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

    /*
     * The first two checks are optimizations that will catch a good
     * many cases.  (1) check against the hostname the user
     * specified.  Odds are good this will either be the mailserver's
     * FQDN or a suffix of it with the mailserver's domain's default
     * host name omitted.  Then check the rest of the `also known as'
     * cache accumulated by previous DNS checks.  This cache is primed
     * by the aka list option.
     *
     * (2) check against the mailserver's FQDN, in case
     * it's not the same as the declared hostname.
     *
     * Either of these on a mail address is definitive.  Only if the
     * name doesn't match either is it time to call the bind library.
     * If this happens odds are good we're looking at an MX name.
     */
    if (str_in_list(&ctl->server.lead_server->names, name))
	return(TRUE);
    else if (strcmp(name, ctl->server.canonical_name) == 0)
	return(TRUE);
    else if (ctl->server.no_dns)
	return(FALSE);

    /*
     * We know DNS service was up at the beginning of this poll cycle.
     * If it's down, our nameserver has crashed.  We don't want to try
     * delivering the current message or anything else from this
     * mailbox until it's back up.
     */
    else if ((he = gethostbyname(name)) != (struct hostent *)NULL)
    {
	if (strcmp(ctl->server.canonical_name, he->h_name) == 0)
	    goto match;
	else
	    return(FALSE);
    }
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
	    error(0, 0,
		"nameserver failure while looking for `%s' during poll of %s.",
		name, ctl->server.names->id);
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
    {
	switch (h_errno)
	{
	case HOST_NOT_FOUND:	/* specified host is unknown */
	case NO_ADDRESS:	/* valid, but does not have an IP address */
	    return(FALSE);
	    break;

	case NO_RECOVERY:	/* non-recoverable name server error */
	case TRY_AGAIN:		/* temporary error on authoritative server */
	default:
	    error(0, 0,
		"nameserver failure while looking for `%s' during poll of %s.",
		name, ctl->server.names->id);
	    ctl->errcount++;
	    longjmp(restart, 2);	/* try again next poll cycle */
	    break;
	}
    }
    else
    {
	for (mxp = mxrecords; mxp->name; mxp++)
	    if (strcmp(ctl->server.canonical_name, mxp->name) == 0)
		goto match;
	return(FALSE);
    match:;
    }

    /* add this name to relevant server's `also known as' list */
    save_str(&ctl->server.lead_server->names, -1, name);
    return(TRUE);
}

static void map_name(name, ctl, xmit_names)
/* add given name to xmit_names if it matches declared localnames */
const char *name;		/* name to map */
struct query *ctl;		/* list of permissible aliases */
struct idlist **xmit_names;	/* list of recipient names parsed out */
{
    const char	*lname;

    lname = idpair_find(&ctl->localnames, name);
    if (!lname && ctl->wildcard)
	lname = name;

    if (lname != (char *)NULL)
    {
	if (outlevel == O_VERBOSE)
	    error(0, 0, "mapped %s to local %s", name, lname);
	save_str(xmit_names, -1, lname);
    }
}

void find_server_names(hdr, ctl, xmit_names)
/* parse names out of a RFC822 header into an ID list */
const char *hdr;		/* RFC822 header in question */
struct query *ctl;		/* list of permissible aliases */
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
		    struct idlist	*idp;

		    /*
		     * Does a trailing segment of the hostname match something
		     * on the localdomains list?  If so, save the whole name
		     * and keep going.
		     */
		    for (idp = ctl->server.localdomains; idp; idp = idp->next)
		    {
			char	*rhs;

			rhs = atsign + 1 + (strlen(atsign) - strlen(idp->id));
			if ((rhs[-1] == '.' || rhs[-1] == '@')
					&& strcmp(rhs, idp->id) == 0)
			{
			    if (outlevel == O_VERBOSE)
				error(0, 0, "passed through %s matching %s", 
				      cp, idp->id);
			    save_str(xmit_names, -1, cp);
			    continue;
			}
		    }

		    /*
		     * Check to see if the right-hand part is an alias
		     * or MX equivalent of the mailserver.  If it's
		     * not, skip this name.  If it is, we'll keep
		     * going and try to find a mapping to a client name.
		     */
		    if (!is_host_alias(atsign+1, ctl))
			continue;
		    atsign[0] = '\0';
		}

		map_name(cp, ctl, xmit_names);
	    } while
		((cp = nxtaddr((char *)NULL)) != (char *)NULL);
    }
}

char *parse_received(struct query *ctl, char *bufp)
/* try to extract */
{
    char *ok;
    static char rbuf[HOSTLEN + USERNAMELEN + 4]; 

    /*
     * Try to extract the real envelope addressee.  We look here
     * specifically for the mailserver's Received line.
     * Note: this will only work for sendmail, or an MTA that
     * shares sendmail's convention for embedding the envelope
     * address in the Received line.  Sendmail itself only
     * does this when the mail has a single recipient.
     */
    if ((ok = strstr(bufp, "by ")) == (char *)NULL)
	ok = (char *)NULL;
    else
    {
	char	*sp, *tp;

	/* extract space-delimited token after "by " */
	for (sp = ok + 3; isspace(*sp); sp++)
	    continue;
	tp = rbuf;
	for (; !isspace(*sp); sp++)
	    *tp++ = *sp;
	*tp = '\0';

	/*
	 * If it's a DNS name of the mail server, look for the
	 * recipient name after a following "for".  Otherwise
	 * punt.
	 */
	if (is_host_alias(rbuf, ctl))
	    ok = strstr(sp, "for ");
	else
	    ok = (char *)NULL;
    }

    if (ok != 0)
    {
	char	*sp, *tp;

	tp = rbuf;
	sp = ok + 4;
	if (*sp == '<')
	    sp++;
	while (*sp && *sp != '>' && *sp != '@' && *sp != ';')
	    if (!isspace(*sp))
		*tp++ = *sp++;
	    else
	    {
		/* uh oh -- whitespace here can't be right! */
		ok = (char *)NULL;
		break;
	    }
	*tp = '\0';
    }

    if (!ok)
	return(NULL);
    else
    {
	if (outlevel == O_VERBOSE)
	    error(0, 0, "found Received address `%s'", rbuf);
	return(rbuf);
    }
}
#endif /* HAVE_RES_SEARCH */

static FILE *smtp_open(struct query *ctl)
/* try to open a socket to the appropriate SMTP server for this query */ 
{
    struct query *lead;

    lead = ctl->lead_smtp; /* go to the SMTP leader for this query */

    /* maybe it's time to close the socket in order to force delivery */
    if (batchlimit && lead->smtp_sockfp && batchcount++ == batchlimit)
    {
	fclose(lead->smtp_sockfp);
	lead->smtp_sockfp = (FILE *)NULL;
	batchcount = 0;
    }

    /* 
     * RFC 1123 requires that the domain name in HELO address is a
     * "valid principal domain name" for the client host.  We
     * violate this with malice aforethought in order to make the
     * Received headers and logging look right.
     *
     * In fact this code relies on the RFC1123 requirement that the
     * SMTP listener must accept messages even if verification of the
     * HELO name fails (RFC1123 section 5.2.5, paragraph 2).
     */

    /* if no socket to this host is already set up, try to open ESMTP */
    if (lead->smtp_sockfp == (FILE *)NULL)
    {
	if ((lead->smtp_sockfp = SockOpen(lead->smtphost, SMTP_PORT)) == (FILE *)NULL)
	    return((FILE *)NULL);
	else if (SMTP_ok(lead->smtp_sockfp) != SM_OK
		 || SMTP_ehlo(lead->smtp_sockfp, 
			      ctl->server.names->id,
			      &lead->server.esmtp_options) != SM_OK)
	{
	    /*
	     * RFC 1869 warns that some listeners hang up on a failed EHLO,
	     * so it's safest not to assume the socket will still be good.
	     */
	    fclose(lead->smtp_sockfp);
	    lead->smtp_sockfp = (FILE *)NULL;
	}
    }

    /* if opening for ESMTP failed, try SMTP */
    if (lead->smtp_sockfp == (FILE *)NULL)
    {
	if ((lead->smtp_sockfp = SockOpen(lead->smtphost, SMTP_PORT)) == (FILE *)NULL)
	    return((FILE *)NULL);
	else if (SMTP_ok(lead->smtp_sockfp) != SM_OK
		 || SMTP_helo(lead->smtp_sockfp, ctl->server.names->id) != SM_OK)
	{
	    fclose(lead->smtp_sockfp);
	    lead->smtp_sockfp = (FILE *)NULL;
	}
    }

    return(lead->smtp_sockfp);
}

static int gen_readmsg(sockfp, len, delimited, ctl, realname)
/* read message content and ship to SMTP or MDA */
FILE *sockfp;		/* to which the server is connected */
long len;		/* length of message */
int delimited;		/* does the protocol use a message delimiter? */
struct query *ctl;	/* query control record */
char *realname;		/* real name of host */
{
    char buf [MSGBUFSIZE+1]; 
    int	from_offs, to_offs, cc_offs, bcc_offs, ctt_offs, env_offs;
    char *headers, *received_for;
    int n, oldlen, ch, sizeticker, delete_ok;
    FILE *sinkfp;
    RETSIGTYPE (*sigchld)();
#ifdef HAVE_GETHOSTBYNAME
    char rbuf[HOSTLEN + USERNAMELEN + 4]; 
#endif /* HAVE_GETHOSTBYNAME */
    char		*cp;
    struct idlist 	*idp, *xmit_names;
    int			good_addresses, bad_addresses;
#ifdef HAVE_RES_SEARCH
    int			no_local_matches = FALSE;
#endif /* HAVE_RES_SEARCH */

    sizeticker = 0;
    delete_ok = TRUE;

    /* read message headers */
    headers = received_for = NULL;
    from_offs = to_offs = cc_offs = bcc_offs = ctt_offs = env_offs = -1;
    oldlen = 0;
    for (;;)
    {
	char *bufp, *line;

	line = xmalloc(sizeof(buf));
	line[0] = '\0';
	do {
	    if (!SockGets(buf, sizeof(buf)-1, sockfp))
		return(PS_SOCKET);
	    vtalarm(ctl->server.timeout);
	    /* leave extra room for reply_hack to play with */
	    line = realloc(line, strlen(line) + strlen(buf) + HOSTLEN + 1);
	    strcat(line, buf);
	} while
	    /* we may need to grab RFC822 continuations */
	    ((ch = SockPeek(sockfp)) == ' ' || ch == '\t');

	/* write the message size dots */
	if ((n = strlen(line)) > 0)
	{
	    sizeticker += n;
	    while (sizeticker >= SIZETICKER)
	    {
		if (outlevel > O_SILENT)
		    error_build(".");
		sizeticker -= SIZETICKER;
	    }
	}
	len -= n;

	/* check for end of headers; don't save terminating line */
	if (line[0] == '\r' && line[1] == '\n')
	{
	    free(line);
	    break;
	}
     
	if (!ctl->no_rewrite)
	    reply_hack(line, realname);

	bufp = line;
	if (!headers)
	{
	    oldlen = strlen(bufp);
	    headers = xmalloc(oldlen + 1);
	    (void) strcpy(headers, bufp);
	    bufp = headers;
	}
	else
	{
	    int	newlen;

	    newlen = oldlen + strlen(bufp);
	    headers = realloc(headers, newlen + 1);
	    if (headers == NULL)
		return(PS_IOERR);
	    strcpy(headers + oldlen, bufp);
	    bufp = headers + oldlen;
	    oldlen = newlen;
	}
	free(line);

	if (from_offs == -1 && !strncasecmp("From:", bufp, 5))
	    from_offs = (bufp - headers);
	else if (from_offs == -1 && !strncasecmp("Resent-From:", bufp, 12))
	    from_offs = (bufp - headers);
	else if (from_offs == -1 && !strncasecmp("Apparently-From:", bufp, 16))
	    from_offs = (bufp - headers);

	else if (!strncasecmp("To:", bufp, 3))
	    to_offs = (bufp - headers);

	else if (env_offs == -1 && !strncasecmp(ctl->server.envelope,
						bufp,
						strlen(ctl->server.envelope)))
	    env_offs = (bufp - headers);

	else if (!strncasecmp("Cc:", bufp, 3))
	    cc_offs = (bufp - headers);

	else if (!strncasecmp("Bcc:", bufp, 4))
	    bcc_offs = (bufp - headers);

	else if (!strncasecmp("Content-Transfer-Encoding:", bufp, 26))
	    ctt_offs = (bufp - headers);

#ifdef HAVE_RES_SEARCH
	else if (MULTIDROP(ctl) && !strncasecmp("Received:", bufp, 9))
	    received_for = parse_received(ctl, bufp);
#endif /* HAVE_RES_SEARCH */
    }

    /*
     * We can now process message headers before reading the text.
     * In fact we have to, as this will tell us where to forward to.
     */

    /* cons up a list of local recipients */
    xmit_names = (struct idlist *)NULL;
    bad_addresses = good_addresses = 0;
#ifdef HAVE_RES_SEARCH
    /* is this a multidrop box? */
    if (MULTIDROP(ctl))
    {
	if (env_offs > -1)	    /* We have the actual envelope addressee */
	    find_server_names(headers + env_offs, ctl, &xmit_names);
	else if (received_for)
	    /*
	     * We have the Received for addressee.  
	     * It has to be a mailserver address, or we
	     * wouldn't have got here.
	     */
	    map_name(received_for, ctl, &xmit_names);
	else
	{
	    /*
	     * We haven't extracted the envelope address.
	     * So check all the header addresses.
	     */
	    if (to_offs > -1)
		find_server_names(headers + to_offs,  ctl, &xmit_names);
	    if (cc_offs > -1)
		find_server_names(headers + cc_offs,  ctl, &xmit_names);
	    if (bcc_offs > -1)
		find_server_names(headers + bcc_offs, ctl, &xmit_names);
	}
	if (!xmit_names)
	{
	    no_local_matches = TRUE;
	    save_str(&xmit_names, -1, user);
	    if (outlevel == O_VERBOSE)
		error(0, 0, 
		      "no local matches, forwarding to %s",
		      user);
	}
    }
    else	/* it's a single-drop box, use first localname */
#endif /* HAVE_RES_SEARCH */
	save_str(&xmit_names, -1, ctl->localnames->id);

    /* time to address the message */
    if (ctl->mda)	/* we have a declared MDA */
    {
	int	length = 0;
	char	*names, *cmd;

	/*
	 * We go through this in order to be able to handle very
	 * long lists of users and (re)implement %s.
	 */
	for (idp = xmit_names; idp; idp = idp->next)
	    length += (strlen(idp->id) + 1);
	names = (char *)alloca(length);
	names[0] = '\0';
	for (idp = xmit_names; idp; idp = idp->next)
	{
	    strcat(names, idp->id);
	    strcat(names, " ");
	}
	cmd = (char *)alloca(strlen(ctl->mda) + length);
	sprintf(cmd, ctl->mda, names);
	if (outlevel == O_VERBOSE)
	    error(0, 0, "about to deliver with: %s", cmd);

#ifdef HAVE_SETEUID
	/*
	 * Arrange to run with user's permissions if we're root.
	 * This will initialize the ownership of any files the
	 * MDA creates properly.  (The seteuid call is available
	 * under all BSDs and Linux)
	 */
	seteuid(ctl->uid);
#endif /* HAVE_SETEUID */

	sinkfp = popen(cmd, "w");

#ifdef HAVE_SETEUID
	/* this will fail quietly if we didn't start as root */
	seteuid(0);
#endif /* HAVE_SETEUID */

	if (!sinkfp)
	{
	    error(0, 0, "MDA open failed");
	    return(PS_IOERR);
	}

	sigchld = signal(SIGCHLD, SIG_DFL);
    }
    else
    {
	char	*ap, *ctt, options[MSGBUFSIZE];
	int	smtperr;

	/* build a connection to the SMTP listener */
	if (!ctl->mda && ((sinkfp = smtp_open(ctl)) == NULL))
	{
	    free_str_list(&xmit_names);
	    error(0, 0, "SMTP connect failed");
	    return(PS_SMTP);
	}

	/*
	 * Compute ESMTP options.  It's a kluge to use nxtaddr()
	 * here because the contents of the Content-Transfer-Encoding
	 * headers isn't semantically an address.  But it has the
	 * desired tokenizing effect.
	 */
	options[0] = '\0';
	if ((ctl->server.esmtp_options & ESMTP_8BITMIME)
	    && (ctt_offs >= 0)
	    && (ctt = nxtaddr(headers + ctt_offs)))
	    if (!strcasecmp(ctt,"7BIT"))
		sprintf(options, " BODY=7BIT", ctt);
	    else if (!strcasecmp(ctt,"8BIT"))
		sprintf(options, " BODY=8BITMIME", ctt);
	if ((ctl->server.esmtp_options & ESMTP_SIZE) && !delimited)
	    sprintf(options + strlen(options), " SIZE=%d", len);

	/*
	 * Try to get the SMTP listener to take the header
	 * From address as MAIL FROM (this makes the logging
	 * nicer).  If it won't, fall back on the calling-user
	 * ID.  This won't affect replies, which use the header
	 * From address anyway.
	 *
	 * RFC 1123 requires that the domain name part of the
	 * MAIL FROM address be "canonicalized", that is a
	 * FQDN or MX but not a CNAME.  We'll assume the From
	 * header is already in this form here (it certainly
	 * is if rewrite is on).  RFC 1123 is silent on whether
	 * a nonexistent hostname part is considered canonical.
	 *
	 * This is a potential problem if the MTAs further
	 * upstream didn't pass canonicalized From lines, *and*
	 * the local SMTP listener insists on them.
	 */
	if (from_offs == -1 || !(ap = nxtaddr(headers + from_offs)))
	    ap = user;
	if (SMTP_from(sinkfp, ap, options) != SM_OK)
	{
	    int smtperr = atoi(smtp_response);

	    if (smtperr >= 400)
		error(0, 0, "SMTP error: %s", smtp_response);

	    /*
	     * There'a one problem with this flow of control;
	     * there's no way to avoid reading the whole message
	     * off the server, even if the MAIL FROM response 
	     * tells us that it's just to be discarded.  We could
	     * fix this under IMAP by reading headers first, then
	     * trying to issue the MAIL FROM, and *then* reading
	     * the body...but POP3 can't do this.
	     */

	    switch (smtperr)
	    {
	    case 571: /* unsolicited email refused */
		/*
		 * SMTP listener explicitly refuses to deliver
		 * mail coming from this address, probably due
		 * to an anti-spam domain exclusion.  Respect
		 * this.  Don't try to ship the message, and
		 * don't prevent it from being deleted.
		 */
		sinkfp = (FILE *)NULL;
		goto skiptext;

	    case 452: /* insufficient system storage */
		/*
		 * Temporary out-of-queue-space condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and suppress deletion so it can be retried on
		 * a future retrieval cycle.
		 */
		delete_ok = FALSE;
		sinkfp = (FILE *)NULL;
		SMTP_rset(sockfp);	/* required by RFC1870 */
		goto skiptext;

	    case 552: /* message exceeds fixed maximum message size */
		/*
		 * Permanent no-go condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and allow it to be deleted.
		 */
		sinkfp = (FILE *)NULL;
		SMTP_rset(sockfp);	/* required by RFC1870 */
		goto skiptext;

	    default:	/* retry with invoking user's address */
		if (SMTP_from(sinkfp, user, options) != SM_OK)
		{
		    error(0,0,"SMTP error: %s", smtp_response);
		    return(PS_SMTP);	/* should never happen */
		}
	    }
	}

	/*
	 * Now list the recipient addressees
	 *
	 * RFC 1123 requires that the domain name part of the
	 * RCPT TO address be "canonicalized", that is a FQDN
	 * or MX but not a CNAME.  RFC1123 doesn't say whether
	 * the FQDN part can be null (as it frequently will be
	 * here), but it's hard to see how this could cause a
	 * problem.
	 */
	for (idp = xmit_names; idp; idp = idp->next)
	    if (SMTP_rcpt(sinkfp, idp->id) == SM_OK)
		good_addresses++;
	    else
	    {
		bad_addresses++;
		idp->val.num = 0;
		error(0, 0, 
		      "SMTP listener doesn't like recipient address `%s'", idp->id);
	    }
	if (!good_addresses && SMTP_rcpt(sinkfp, user) != SM_OK)
	{
	    error(0, 0, 
		  "can't even send to calling user!");
	    return(PS_SMTP);
	}

	/* tell it we're ready to send data */
	SMTP_data(sinkfp);

    skiptext:;
    }

    /* write all the headers */
    if (ctl->stripcr)
    {
	char	*sp, *tp;

	for (sp = tp = headers; *sp; sp++)
	    if (*sp != '\r')
		*tp++ =  *sp;
	*tp = '\0';

    }

    /* write all the headers */
    if (sinkfp)
    {
	if (ctl->mda)
	    n = fwrite(headers, 1, strlen(headers), sinkfp);
	else
	    n = SockWrite(headers, 1, strlen(headers), sinkfp);

	if (n < 0)
	{
	    free(headers);
	    headers = NULL;
	    error(0, errno, "writing RFC822 headers");
	    if (ctl->mda)
	    {
		pclose(sinkfp);
		signal(SIGCHLD, sigchld);
	    }
	    return(PS_IOERR);
	}
	else if (outlevel == O_VERBOSE)
	    fputs("#", stderr);
    }
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

	/* ship out the error line */
	if (ctl->stripcr)
	{
	    char	*sp, *tp;

	    for (sp = tp = errmsg; *sp; sp++)
		if (*sp != '\r')
		    *tp++ =  *sp;
	    *tp = '\0';
	}

	if (sinkfp)
	{
	    if (ctl->mda)
		fwrite(errmsg, 1, strlen(errmsg), sinkfp);
	    else
		SockWrite(errmsg, 1, strlen(errmsg), sinkfp);
	}
    }

    free_str_list(&xmit_names);

    /* issue the delimiter line */
    if (sinkfp)
    {
	if (ctl->mda)
	    fputc('\n', sinkfp);
	else
	    SockWrite("\r\n", 1, 2, sinkfp);
    }

    /*
     *  Body processing starts here
     */

    /* pass through the text lines */
    while (delimited || len > 0)
    {
	if (!SockGets(buf, sizeof(buf)-1, sockfp))
	    return(PS_SOCKET);
	vtalarm(ctl->server.timeout);

	/* write the message size dots */
	if ((n = strlen(buf)) > 0)
	{
	    sizeticker += n;
	    while (sizeticker >= SIZETICKER)
	    {
		if (outlevel > O_SILENT)
		    error_build(".");
		sizeticker -= SIZETICKER;
	    }
	}
	len -= n;

	/* check for end of message */
	if (delimited && *buf == '.')
	    if (buf[1] == '\r' && buf[2] == '\n')
		break;

	/* ship out the text line */
	if (sinkfp)
	{
	    /* SMTP byte-stuffing */
	    if (*buf == '.')
		if (ctl->mda)
		    fputs(".", sinkfp);
		else
		    SockWrite(buf, 1, 1, sinkfp);

	    if (ctl->stripcr)
	    {
		char	*sp, *tp;

		for (sp = tp = buf; *sp; sp++)
		    if (*sp != '\r')
			*tp++ =  *sp;
		*tp = '\0';
	    }

	    if (ctl->mda)
		n = fwrite(buf, 1, strlen(buf), sinkfp);
	    else if (sinkfp)
		n = SockWrite(buf, 1, strlen(buf), sinkfp);

	    if (n < 0)
	    {
		error(0, errno, "writing message text");
		if (ctl->mda)
		{
		    pclose(sinkfp);
		    signal(SIGCHLD, sigchld);
		}
		return(PS_IOERR);
	    }
	    else if (outlevel == O_VERBOSE)
		fputc('*', stderr);
	}
    }

    /*
     * End-of-message processing starts here
     */

    if (outlevel == O_VERBOSE)
	fputc('\n', stderr);

    if (ctl->mda)
    {
	int rc;

	/* close the delivery pipe, we'll reopen before next message */
	rc = pclose(sinkfp);
	signal(SIGCHLD, sigchld);
	if (rc)
	{
	    error(0, 0, "MDA exited abnormally or returned nonzero status");
	    return(PS_IOERR);
	}
    }
    else if (sinkfp)
    {
	/* write message terminator */
	if (SMTP_eom(sinkfp) != SM_OK)
	{
	    error(0, 0, "SMTP listener refused delivery");
	    return(PS_TRANSIENT);
	}
    }

    return(delete_ok ? PS_SUCCESS : PS_TRANSIENT);
}

#ifdef KERBEROS_V4
int
kerberos_auth (socket, canonical) 
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
	error(0, 0, "kerberos error %s", (krb_get_err_text (rem)));
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
    int ok, js, pst;
    char *msg, *sp, *cp, realname[HOSTLEN];
    void (*sigsave)();

#ifndef KERBEROS_V4
    if (ctl->server.authenticate == A_KERBEROS)
    {
	error(0, 0, "Kerberos support not linked.");
	return(PS_ERROR);
    }
#endif /* KERBEROS_V4 */

    /* lacking methods, there are some options that may fail */
    if (!proto->is_old)
    {
	/* check for unsupported options */
	if (ctl->flush) {
	    error(0, 0,
		    "Option --flush is not supported with %s",
		    proto->name);
	    return(PS_SYNTAX);
	}
	else if (ctl->fetchall) {
	    error(0, 0,
		    "Option --all is not supported with %s",
		    proto->name);
	    return(PS_SYNTAX);
	}
    }
    if (!proto->getsizes && ctl->limit)
    {
	error(0, 0,
		"Option --limit is not supported with %s",
		proto->name);
	return(PS_SYNTAX);
    }

    protocol = proto;
    tagnum = 0;
    tag[0] = '\0';	/* nuke any tag hanging out from previous query */
    ok = 0;
    error_init(poll_interval == 0 && !logfile);

    /* set up the server-nonresponse timeout */
    sigsave = signal(SIGVTALRM, vtalarm_handler);
    vtalarm(mytimeout = ctl->server.timeout);

    if ((js = setjmp(restart)) == 1)
    {
	error(0, 0,
		"timeout after %d seconds waiting for %s.",
		ctl->server.timeout, ctl->server.names->id);
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
	/* execute pre-initialization command, if any */
	if (ctl->preconnect && (ok = system(ctl->preconnect)))
	{
	    sprintf(buf, "pre-connection command failed with status %d", ok);
	    error(0, 0, buf);
	    ok = PS_SYNTAX;
	    goto closeUp;
	}

	/* open a socket to the mail server */
	if (!(sockfp = SockOpen(ctl->server.names->id,
		     ctl->server.port ? ctl->server.port : protocol->port)))
	{
#ifndef EHOSTUNREACH
#define EHOSTUNREACH (-1)
#endif
	    if (errno != EHOSTUNREACH)
		error(0, errno, "connecting to host");
	    ok = PS_SOCKET;
	    goto closeUp;
	}

#ifdef KERBEROS_V4
	if (ctl->authenticate == A_KERBEROS)
	{
	    ok = kerberos_auth(fileno(sockfp), ctl->server.canonical_name);
 	    if (ok != 0)
		goto cleanUp;
	    vtalarm(ctl->server.timeout);
	}
#endif /* KERBEROS_V4 */

	/* accept greeting message from mail server */
	ok = (protocol->parse_response)(sockfp, buf);
	if (ok != 0)
	    goto cleanUp;
	vtalarm(ctl->server.timeout);

	/*
	 * Try to parse the host's actual name out of the greeting
	 * message.  We do this so that the progress messages will
	 * make sense even if the connection is indirected through
	 * ssh. *Do* use this for hacking reply headers, but *don't*
	 * use it for error logging, as the names in the log should
	 * correlate directly back to rc file entries.
	 *
	 * This assumes that the first space-delimited token found
	 * that contains at least two dots (with the characters on
	 * each side of the dot alphanumeric to exclude version
	 * numbers) is the hostname.  The hostname candidate may not
	 * contain @ -- if it does it's probably a mailserver
	 * maintainer's name.  If no such token is found, fall back on
	 * the .fetchmailrc id.
	 */
	pst = 0;
	for (cp = buf; *cp; cp++)
	{
	    switch (pst)
	    {
	    case 0:		/* skip to end of current token */
		if (*cp == ' ')
		    pst = 1;
		break;

	    case 1:		/* look for blank-delimited token */
		if (*cp != ' ')
		{
		    sp = cp;
		    pst = 2;
		}
		break;

	    case 2:		/* look for first dot */
		if (*cp == '@')
		    pst = 0;
		else if (*cp == ' ')
		    pst = 1;
		else if (*cp == '.' && isalpha(cp[1]) && isalpha(cp[-1]))
		    pst = 3;
		break;

	    case 3:		/* look for second dot */
		if (*cp == '@')
		    pst = 0;
		else if (*cp == ' ')
		    pst = 1;
		else if (*cp == '.' && isalpha(cp[1]) && isalpha(cp[-1]))
		    pst = 4;
		break;

	    case 4:		/* look for trailing space */
		if (*cp == '@')
		    pst = 0;
		else if (*cp == ' ')
		{
		    pst = 5;
		    goto done;
		}
		break;
	    }
	}
    done:
	if (pst == 5)
	{
	    char	*tp = realname;

	    while (sp < cp)
		*tp++ = *sp++;
	    *tp = '\0';
	}
	else
	    strcpy(realname, ctl->server.names->id);

	/* try to get authorized to fetch mail */
	shroud = ctl->password;
	ok = (protocol->getauth)(sockfp, ctl, buf);
	shroud = (char *)NULL;
	if (ok == PS_ERROR)
	    ok = PS_AUTHFAIL;
	if (ok != 0)
	{
	    error(0, 0, "Authorization failure on %s@%s", 
		  ctl->remotename,
		  realname);
	    goto cleanUp;
	}
	vtalarm(ctl->server.timeout);

	/* compute number of messages and number of new messages waiting */
	ok = (protocol->getrange)(sockfp, ctl, &count, &new);
	if (ok != 0)
	    goto cleanUp;
	vtalarm(ctl->server.timeout);

	/* show user how many messages we downloaded */
	if (outlevel > O_SILENT)
	    if (count == 0)
		error(0, 0, "No mail from %s@%s", 
			ctl->remotename,
			realname);
	    else
	    {
		if (new != -1 && (count - new) > 0)
		    error(0, 0, "%d message%s (%d seen) from %s@%s.",
		    		count, count > 1 ? "s" : "", count-new,
				ctl->remotename,
				realname);
		else
		    error(0, 0, "%d message%s from %s@%s.", count, count > 1 ? "s" : "",
				ctl->remotename,
				realname);
	    }

	/* we may need to get sizes in order to check message limits */
	msgsizes = (int *)NULL;
	if (!ctl->fetchall && proto->getsizes && ctl->limit)
	{
	    msgsizes = (int *)alloca(sizeof(int) * count);

	    ok = (proto->getsizes)(sockfp, count, msgsizes);
	    if (ok != 0)
		goto cleanUp;
	    vtalarm(ctl->server.timeout);
	}

	if (check_only)
	{
	    if (new == -1 || ctl->fetchall)
		new = count;
	    ok = ((new > 0) ? PS_SUCCESS : PS_NOMAIL);
	    goto cleanUp;
	}
	else if (count > 0)
	{    
	    /*
	     * What forces this code is that in POP3 and IMAP2BIS you can't
	     * fetch a message without having it marked `seen'.  In IMAP4,
	     * on the other hand, you can (peek_capable is set to convey
	     * this).
	     *
	     * The result of being unable to peek is that if there's
	     * any kind of transient error (DNS lookup failure, or
	     * sendmail refusing delivery due to process-table limits)
	     * the message will be marked "seen" on the server without
	     * having been delivered.  This is not a big problem if
	     * fetchmail is running in foreground, because the user
	     * will see a "skipped" message when it next runs and get
	     * clued in.
	     *
	     * But in daemon mode this leads to the message being silently
	     * ignored forever.  This is not acceptable.
	     *
	     * We compensate for this by checking the error count from the 
	     * previous pass and forcing all messages to be considered new
	     * if it's nonzero.
	     */
	    int	force_retrieval = !peek_capable && (ctl->errcount > 0);

	    ctl->errcount = 0;

	    /* read, forward, and delete messages */
	    for (num = 1; num <= count; num++)
	    {
		int	toolarge = msgsizes && (msgsizes[num-1] > ctl->limit);
		int	fetch_it = ctl->fetchall ||
		    (!toolarge && (force_retrieval || !(protocol->is_old && (protocol->is_old)(sockfp,ctl,num))));
		int	suppress_delete = FALSE;

		/* we may want to reject this message if it's old */
		if (!fetch_it)
		{
		    if (outlevel > O_SILENT)
		    {
			error_build("skipping message %d", num);
			if (toolarge)
			    error_build(" (oversized, %d bytes)", msgsizes[num-1]);
		    }
		}
		else
		{
		    /* request a message */
		    ok = (protocol->fetch)(sockfp, ctl, num, &len);
		    if (ok != 0)
			goto cleanUp;
		    vtalarm(ctl->server.timeout);

		    if (outlevel > O_SILENT)
		    {
			error_build("reading message %d", num);
			if (len > 0)
			    error_build(" (%d bytes)", len);
			if (outlevel == O_VERBOSE)
			    error_complete(0, 0, "");
			else
			    error_build(" ");
		    }

		    /* read the message and ship it to the output sink */
		    ok = gen_readmsg(sockfp,
				     len, 
				     protocol->delimited,
				     ctl,
				     realname);
		    if (ok == PS_TRANSIENT)
			suppress_delete = TRUE;
		    else if (ok)
			goto cleanUp;
		    vtalarm(ctl->server.timeout);

		    /* tell the server we got it OK and resynchronize */
		    if (protocol->trail)
		    {
			ok = (protocol->trail)(sockfp, ctl, num);
			if (ok != 0)
			    goto cleanUp;
			vtalarm(ctl->server.timeout);
		    }
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
		    && !suppress_delete
		    && (fetch_it ? !ctl->keep : ctl->flush))
		{
		    deletions++;
		    if (outlevel > O_SILENT) 
			error_complete(0, 0, " flushed");
		    ok = (protocol->delete)(sockfp, ctl, num);
		    if (ok != 0)
			goto cleanUp;
		    vtalarm(ctl->server.timeout);
		    delete_str(&ctl->newsaved, num);
		}
		else if (outlevel > O_SILENT) 
		    error_complete(0, 0, " not flushed");

		/* perhaps this as many as we're ready to handle */
		if (ctl->fetchlimit && ctl->fetchlimit <= num)
		    break;
	    }

	    ok = gen_transact(sockfp, protocol->exit_cmd);
	    if (ok == 0)
		ok = PS_SUCCESS;
	    vtalarm(0);
	    fclose(sockfp);
	    goto closeUp;
	}
	else {
	    ok = gen_transact(sockfp, protocol->exit_cmd);
	    if (ok == 0)
		ok = PS_NOMAIL;
	    vtalarm(0);
	    fclose(sockfp);
	    goto closeUp;
	}

    cleanUp:
	vtalarm(ctl->server.timeout);
	if (ok != 0 && ok != PS_SOCKET)
	    gen_transact(sockfp, protocol->exit_cmd);
	vtalarm(0);
	fclose(sockfp);
    }

    switch (ok)
    {
    case PS_SOCKET:
	msg = "socket";
	break;
    case PS_AUTHFAIL:
	msg = "authorization";
	break;
    case PS_SYNTAX:
	msg = "missing or bad RFC822 header";
	break;
    case PS_IOERR:
	msg = "MDA";
	break;
    case PS_ERROR:
	msg = "client/server synchronization";
	break;
    case PS_PROTOCOL:
	msg = "client/server protocol";
	break;
    case PS_SMTP:
	msg = "SMTP transaction";
	break;
    case PS_UNDEFINED:
	error(0, 0, "undefined");
	break;
    }
    if (ok==PS_SOCKET || ok==PS_AUTHFAIL || ok==PS_SYNTAX || ok==PS_IOERR
		|| ok==PS_ERROR || ok==PS_PROTOCOL || ok==PS_SMTP)
	error(0, 0, "%s error while fetching from %s", msg, ctl->server.names->id);

closeUp:
    signal(SIGVTALRM, sigsave);
    return(ok);
}

#if defined(HAVE_STDARG_H)
void gen_send(FILE *sockfp, char *fmt, ... )
/* assemble command in printf(3) style and send to the server */
#else
void gen_send(sockfp, fmt, va_alist)
/* assemble command in printf(3) style and send to the server */
FILE *sockfp;		/* socket to which server is connected */
const char *fmt;	/* printf-style format */
va_dcl
#endif
{
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
    SockWrite(buf, 1, strlen(buf), sockfp);

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && (cp = strstr(buf, shroud)))
	    memset(cp, '*', strlen(shroud));
	buf[strlen(buf)-1] = '\0';
	error(0, 0, "%s> %s", protocol->name, buf);
    }
}

int gen_recv(sockfp, buf, size)
/* get one line of input from the server */
FILE *sockfp;	/* socket to which server is connected */
char *buf;	/* buffer to receive input */
int size;	/* length of buffer */
{
    if (!SockGets(buf, size, sockfp))
	return(PS_SOCKET);
    else
    {
	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\r';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "%s< %s", protocol->name, buf);
	return(PS_SUCCESS);
    }
}

#if defined(HAVE_STDARG_H)
int gen_transact(FILE *sockfp, char *fmt, ... )
/* assemble command in printf(3) style, send to server, accept a response */
#else
int gen_transact(sockfp, fmt, va_alist)
/* assemble command in printf(3) style, send to server, accept a response */
FILE *sockfp;		/* socket to which server is connected */
const char *fmt;	/* printf-style format */
va_dcl
#endif
{
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
    SockWrite(buf, 1, strlen(buf), sockfp);

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && (cp = strstr(buf, shroud)))
	    memset(cp, '*', strlen(shroud));
	buf[strlen(buf)-1] = '\0';
	error(0, 0, "%s> %s", protocol->name, buf);
    }

    /* we presume this does its own response echoing */
    ok = (protocol->parse_response)(sockfp, buf);
    vtalarm(mytimeout);

    return(ok);
}

/* driver.c ends here */
