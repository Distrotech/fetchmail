/*
 * driver.c -- generic driver for mail fetch method protocols
 *
 * Copyright 1997 by Eric S. Raymond
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
#if defined(HAVE_SYS_ITIMER_H)
#include <sys/itimer.h>
#endif
#include  <sys/time.h>
#include  <signal.h>

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#include "mx.h"
#endif /* HAVE_GETHOSTBYNAME */

#ifdef SUNOS
#include <memory.h>
#endif

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

int fetchlimit;		/* how often to tear down the server connection */
int batchcount;		/* count of messages sent in current batch */
bool peek_capable;	/* can we peek for better error recovery? */

static const struct method *protocol;
static jmp_buf	restart;

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "a%04d", ++tagnum), tag)

static char *shroud;	/* string to shroud in debug output, if  non-NULL */
static int mytimeout;	/* value of nonreponse timeout */

static void set_timeout(int timeleft)
/* reset the nonresponse-timeout */
{
    struct itimerval ntimeout;

    ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
    ntimeout.it_value.tv_sec  = timeleft;
    ntimeout.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &ntimeout, (struct itimerval *)NULL);
}

static void timeout_handler (int signal)
/* handle server-timeout SIGALRM signal */
{
    longjmp(restart, 1);
}

#define XMIT_ACCEPT		1
#define XMIT_REJECT		2
#define XMIT_ANTISPAM		3	
static int accept_count, reject_count;

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
    else if (!ctl->server.dns)
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
	save_str(xmit_names, XMIT_ACCEPT, lname);
	accept_count++;
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
	char	*cp;

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

			rhs = atsign + (strlen(atsign) - strlen(idp->id));
			if ((rhs[-1] == '.' || rhs[-1] == '@')
					&& strcasecmp(rhs, idp->id) == 0)
			{
			    if (outlevel == O_VERBOSE)
				error(0, 0, "passed through %s matching %s", 
				      cp, idp->id);
			    save_str(xmit_names, XMIT_ACCEPT, cp);
			    accept_count++;
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
		    {
			save_str(xmit_names, XMIT_REJECT, cp);
			reject_count++;
			continue;
		    }
		    atsign[0] = '\0';
		}

		map_name(cp, ctl, xmit_names);
	    } while
		((cp = nxtaddr((char *)NULL)) != (char *)NULL);
    }
}

char *parse_received(struct query *ctl, char *bufp)
/* try to extract real addressee from the Received line */
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

int smtp_open(struct query *ctl)
/* try to open a socket to the appropriate SMTP server for this query */ 
{
    struct idlist	*idp;

    /* maybe it's time to close the socket in order to force delivery */
    if (ctl->batchlimit > 0 && (ctl->smtp_socket != -1) && batchcount++ == ctl->batchlimit)
    {
	close(ctl->smtp_socket);
	ctl->smtp_socket = -1;
	batchcount = 0;
    }

    /* run down the SMTP hunt list looking for a server that's up */
    for (idp = ctl->smtphunt; idp; idp = idp->next)
    {
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
	if (ctl->smtp_socket == -1)
	{
	    if ((ctl->smtp_socket = SockOpen(idp->id,SMTP_PORT)) == -1)
		continue;
	    else if (SMTP_ok(ctl->smtp_socket) != SM_OK
		     || SMTP_ehlo(ctl->smtp_socket, 
				  ctl->server.names->id,
				  &ctl->server.esmtp_options) != SM_OK)
	    {
		/*
		 * RFC 1869 warns that some listeners hang up on a failed EHLO,
		 * so it's safest not to assume the socket will still be good.
		 */
		close(ctl->smtp_socket);
		ctl->smtp_socket = -1;
	    }
	    else
	    {
		ctl->smtphost = idp->id;
		break;
	    }
	}

	/* if opening for ESMTP failed, try SMTP */
	if (ctl->smtp_socket == -1)
	{
	    if ((ctl->smtp_socket = SockOpen(idp->id,SMTP_PORT)) == -1)
		continue;
	    else if (SMTP_ok(ctl->smtp_socket) != SM_OK
		     || SMTP_helo(ctl->smtp_socket, ctl->server.names->id) != SM_OK)
	    {
		close(ctl->smtp_socket);
		ctl->smtp_socket = -1;
	    }
	    else
	    {
		ctl->smtphost = idp->id;
		break;
	    }
	}
    }

    return(ctl->smtp_socket);
}

/* these are shared by readheaders and readbody */
static FILE *sinkfp;
static RETSIGTYPE (*sigchld)();
static int sizeticker;

static int readheaders(sock, len, ctl, realname)
/* read message headers and ship to SMTP or MDA */
int sock;		/* to which the server is connected */
long len;		/* length of message */
struct query *ctl;	/* query control record */
char *realname;		/* real name of host */
{
    char buf[MSGBUFSIZE+1], return_path[MSGBUFSIZE+1]; 
    int	from_offs, to_offs, cc_offs, bcc_offs, ctt_offs, env_offs;
    char *headers, *received_for;
    int n, linelen, oldlen, ch, remaining;
    char		*cp;
    struct idlist 	*idp, *xmit_names;
    bool			good_addresses, bad_addresses, has_nuls;
#ifdef HAVE_RES_SEARCH
    bool		no_local_matches = FALSE;
#endif /* HAVE_RES_SEARCH */
    int			olderrs;

    sizeticker = 0;
    has_nuls = FALSE;
    return_path[0] = '\0';
    olderrs = ctl->errcount;

    /* read message headers */
    headers = received_for = NULL;
    from_offs = to_offs = cc_offs = bcc_offs = ctt_offs = env_offs = -1;
    oldlen = 0;
    for (remaining = len; remaining > 0; remaining -= linelen)
    {
	char *line;

	line = xmalloc(sizeof(buf));
	linelen = 0;
	line[0] = '\0';
	do {
	    if ((n = SockRead(sock, buf, sizeof(buf)-1)) == -1)
		return(PS_SOCKET);
	    linelen += n;

	    /* lines may not be properly CRLF terminated; fix this for qmail */
	    if (ctl->forcecr)
	    {
		cp = buf + strlen(buf) - 1;
		if (*cp == '\n' && (cp == buf || cp[-1] != '\r'))
		{
		    *cp++ = '\r';
		    *cp++ = '\n';
		    *cp++ = '\0';
		}
	    }

	    set_timeout(ctl->server.timeout);
	    /* leave extra room for reply_hack to play with */
	    line = (char *) realloc(line, strlen(line) + strlen(buf) + HOSTLEN + 1);
	    strcat(line, buf);
	    if (line[0] == '\r' && line[1] == '\n')
		break;
	} while
	    /* we may need to grab RFC822 continuations */
	    ((ch = SockPeek(sock)) == ' ' || ch == '\t');

	/* write the message size dots */
	if ((outlevel > O_SILENT && outlevel < O_VERBOSE) && linelen > 0)
	{
	    sizeticker += linelen;
	    while (sizeticker >= SIZETICKER)
	    {
		error_build(".");
		sizeticker -= SIZETICKER;
	    }
	}

	if (linelen != strlen(line))
	    has_nuls = TRUE;

	/* check for end of headers; don't save terminating line */
	if (line[0] == '\r' && line[1] == '\n')
	{
	    free(line);
	    break;
	}
     
	/*
	 * This code prevents fetchmail from becoming an accessory after
	 * the fact to upstream sendmails with the `E' option on.  This
	 * can result in an escaped Unix From_ line at the beginning of
	 * the headers.  If fetchmail just passes it through, the client
	 * listener may think the message has *no* headers (since the first)
	 * line it sees doesn't look RFC822-conformant) and fake up a set.
	 *
	 * What the user would see in this case is bogus (synthesized)
	 * headers, followed by a blank line, followed by the >From, 
	 * followed by the real headers, followed by a blank line,
	 * followed by text.
	 *
	 * We forestall this lossage by tossing anything that looks
	 * like an escaped From_ line in headers.  These aren't RFC822
	 * so our conscience is clear...
	 */
	if (!strncasecmp(line, ">From ", 6))
	{
	    free(line);
	    continue;
	}

	/*
	 * OK, this is messy.  If we're forwarding by SMTP, it's the
	 * SMTP-receiver's job (according to RFC821, page 22, section
	 * 4.1.1) to generate a Return-Path line on final delivery.
	 * The trouble is, we've already got one because the
	 * mailserver's SMTP thought *it* was responsible for final
	 * delivery.
	 *
	 * Stash away the contents of Return-Path for use in generating
	 * MAIL FROM later on, then prevent the header from being saved
	 * with the others.  In effect, we strip it off here.
	 *
	 * If the SMTP server conforms to the standards, and fetchmail gets the
	 * envelope sender from the Return-Path, the new Return-Path should be
	 * exactly the same as the original one.
	 */
	if (!ctl->mda && !strncasecmp("Return-Path:", line, 12))
	{
	    strcpy(return_path, nxtaddr(line));
	    free(line);
	    continue;
	}

	if (ctl->rewrite)
	    reply_hack(line, realname);

	if (!headers)
	{
	    oldlen = strlen(line);
	    headers = xmalloc(oldlen + 1);
	    (void) strcpy(headers, line);
	    free(line);
	    line = headers;
	}
	else
	{
	    int	newlen;

	    newlen = oldlen + strlen(line);
	    headers = (char *) realloc(headers, newlen + 1);
	    if (headers == NULL)
		return(PS_IOERR);
	    strcpy(headers + oldlen, line);
	    free(line);
	    line = headers + oldlen;
	    oldlen = newlen;
	}

	if (from_offs == -1 && !strncasecmp("From:", line, 5))
	    from_offs = (line - headers);
	else if (from_offs == -1 && !strncasecmp("Resent-From:", line, 12))
	    from_offs = (line - headers);
	else if (from_offs == -1 && !strncasecmp("Apparently-From:", line, 16))
	    from_offs = (line - headers);

	else if (!strncasecmp("To:", line, 3))
	    to_offs = (line - headers);

	else if (ctl->server.envelope != STRING_DISABLED && env_offs == -1
		 && !strncasecmp(ctl->server.envelope,
						line,
						strlen(ctl->server.envelope)))
	    env_offs = (line - headers);

	else if (!strncasecmp("Cc:", line, 3))
	    cc_offs = (line - headers);

	else if (!strncasecmp("Bcc:", line, 4))
	    bcc_offs = (line - headers);

	else if (!strncasecmp("Content-Transfer-Encoding:", line, 26))
	    ctt_offs = (line - headers);

#ifdef HAVE_RES_SEARCH
	else if (ctl->server.envelope != STRING_DISABLED && MULTIDROP(ctl) && !received_for && !strncasecmp("Received:", line, 9))
	    received_for = parse_received(ctl, line);
#endif /* HAVE_RES_SEARCH */
    }

    /*
     * Hack time.  If the first line of the message was blank, with no headers
     * (this happens occasionally due to bad gatewaying software) cons up
     * a set of fake headers.  
     *
     * If you modify the fake header template below, be sure you don't
     * make either From or To address @-less, otherwise the reply_hack
     * logic will do bad things.
     */
    if (headers == (char *)NULL)
    {
	sprintf(buf, 
	"From: <FETCHMAIL-DAEMON@%s>\r\nTo: %s@localhost\r\nSubject: Headerless mail from %s's mailbox on %s\r\n",
		fetchmailhost, user, ctl->remotename, realname);
	headers = xstrdup(buf);
    }

    /*
     * We can now process message headers before reading the text.
     * In fact we have to, as this will tell us where to forward to.
     */

    /* cons up a list of local recipients */
    xmit_names = (struct idlist *)NULL;
    bad_addresses = good_addresses = accept_count = reject_count = 0;
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
	if (!accept_count)
	{
	    no_local_matches = TRUE;
	    save_str(&xmit_names, XMIT_ACCEPT, user);
	    if (outlevel == O_VERBOSE)
		error(0, 0, 
		      "no local matches, forwarding to %s",
		      user);
	}
    }
    else	/* it's a single-drop box, use first localname */
#endif /* HAVE_RES_SEARCH */
	save_str(&xmit_names, XMIT_ACCEPT, ctl->localnames->id);


    /*
     * Time to either address the message or decide we can't deliver it yet.
     */
    if (ctl->errcount > olderrs)	/* there were DNS errors above */
    {
	if (outlevel == O_VERBOSE)
	    error(0,0, "forwarding and deletion suppressed due to DNS errors");
	free(headers);
	return(PS_TRANSIENT);
    }
    else if (ctl->mda)		/* we have a declared MDA */
    {
	int	length = 0;
	char	*names, *cmd;

	/*
	 * We go through this in order to be able to handle very
	 * long lists of users and (re)implement %s.
	 */
	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.num == XMIT_ACCEPT)
		length += (strlen(idp->id) + 1);
	names = (char *)alloca(length);
	names[0] = '\0';
	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.num == XMIT_ACCEPT)
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
	    error(0, -1, "MDA open failed");
	    return(PS_IOERR);
	}

	sigchld = signal(SIGCHLD, SIG_DFL);
    }
    else
    {
	char	*ap, *ctt, options[MSGBUFSIZE];

	/* build a connection to the SMTP listener */
	if ((smtp_open(ctl) == -1))
	{
	    free_str_list(&xmit_names);
	    error(0, -1, "SMTP connect to %s failed",
		  ctl->smtphost ? ctl->smtphost : "localhost");
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
		sprintf(options, " BODY=7BIT");
	    else if (!strcasecmp(ctt,"8BIT"))
		sprintf(options, " BODY=8BITMIME");
	if ((ctl->server.esmtp_options & ESMTP_SIZE))
	    sprintf(options + strlen(options), " SIZE=%ld", len);

	/*
	 * If there is a Return-Path address on the message, this was
	 * almost certainly the MAIL FROM address given the originating
	 * sendmail.  This is the best thing to use for logging the
	 * message origin (it sets up the right behavior for bounces and
	 * mailing lists).  Otherwise, take the From address.
	 *
	 * Try to get the SMTP listener to take the Return-Path or
	 * From address as MAIL FROM .  If it won't, fall back on the
	 * calling-user ID.  This won't affect replies, which use the
	 * header From address anyway.
	 *
	 * RFC 1123 requires that the domain name part of the
	 * MAIL FROM address be "canonicalized", that is a
	 * FQDN or MX but not a CNAME.  We'll assume the From
	 * header is already in this form here (it certainly
	 * is if rewrite is on).  RFC 1123 is silent on whether
	 * a nonexistent hostname part is considered canonical.
	 *
	 * This is a potential problem if the MTAs further upstream
	 * didn't pass canonicalized From/Return-Path lines, *and* the
	 * local SMTP listener insists on them.
	 */
	ap = (char *)NULL;
	if (return_path[0])
	    ap = return_path;
	else if (from_offs == -1 || !(ap = nxtaddr(headers + from_offs)))
	    ap = user;
	if (SMTP_from(ctl->smtp_socket, ap, options) != SM_OK)
	{
	    int smtperr = atoi(smtp_response);

	    /*
	     * Suppress error message only if the response specifically 
	     * means `excluded for policy reasons'.  We *should* see
	     * an error when the return code is less specific.
	     */
	    if (smtperr >= 400 && smtperr != 571)
		error(0, -1, "SMTP error: %s", smtp_response);

	    switch (smtperr)
	    {
	    case 571:	/* sendmail's "unsolicited email refused" */
	    case 501:	/* exim's old antispam response */
	    case 550:	/* exim's new antispam response (temporary) */
		/*
		 * SMTP listener explicitly refuses to deliver
		 * mail coming from this address, probably due
		 * to an anti-spam domain exclusion.  Respect
		 * this.  Don't try to ship the message, and
		 * don't prevent it from being deleted.
		 */
		free(headers);
		return(PS_REFUSED);

	    case 452: /* insufficient system storage */
		/*
		 * Temporary out-of-queue-space condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and suppress deletion so it can be retried on
		 * a future retrieval cycle.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		free(headers);
		return(PS_TRANSIENT);

	    case 552: /* message exceeds fixed maximum message size */
		/*
		 * Permanent no-go condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and allow it to be deleted.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		free(headers);
		return(PS_REFUSED);

	    default:	/* retry with invoking user's address */
		if (SMTP_from(ctl->smtp_socket, user, options) != SM_OK)
		{
		    error(0, -1, "SMTP error: %s", smtp_response);
		    free(headers);
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
	    if (idp->val.num == XMIT_ACCEPT)
		if (SMTP_rcpt(ctl->smtp_socket, idp->id) == SM_OK)
		    good_addresses++;
		else
		{
		    bad_addresses++;
		    idp->val.num = XMIT_ANTISPAM;
		    error(0, 0, 
			  "SMTP listener doesn't like recipient address `%s'", idp->id);
		}
	if (!good_addresses && SMTP_rcpt(ctl->smtp_socket, user) != SM_OK)
	{
	    error(0, 0, 
		  "can't even send to calling user!");
	    free(headers);
	    return(PS_SMTP);
	}

	/* tell it we're ready to send data */
	SMTP_data(ctl->smtp_socket);
    }

    /* we may need to strip carriage returns */
    if (ctl->stripcr)
    {
	char	*sp, *tp;

	for (sp = tp = headers; *sp; sp++)
	    if (*sp != '\r')
		*tp++ =  *sp;
	*tp = '\0';

    }

    /* write all the headers */
    n = 0;
    if (ctl->mda && sinkfp)
	n = fwrite(headers, 1, strlen(headers), sinkfp);
    else if (ctl->smtp_socket != -1)
	n = SockWrite(ctl->smtp_socket, headers, strlen(headers));
    free(headers);

    if (n < 0)
    {
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

    /* write error notifications */
#ifdef HAVE_RES_SEARCH
    if (no_local_matches || has_nuls || bad_addresses)
#else
    if (has_nuls || bad_addresses)
#endif /* HAVE_RES_SEARCH */
    {
	int	errlen = 0;
	char	errhd[USERNAMELEN + POPBUFSIZE], *errmsg;

	errmsg = errhd;
	(void) strcpy(errhd, "X-Fetchmail-Warning: ");
#ifdef HAVE_RES_SEARCH
	if (no_local_matches)
	{
	    if (reject_count != 1)
		strcat(errhd, "no recipient addresses matched declared local names");
	    else
	    {
		for (idp = xmit_names; idp; idp = idp->next)
		    if (idp->val.num == XMIT_REJECT)
			break;
		sprintf(errhd+strlen(errhd), "recipient address %s didn't match any local name", idp->id);
	    }
	}
#endif /* HAVE_RES_SEARCH */

	if (has_nuls)
	{
	    if (errhd[sizeof("X-Fetchmail-Warning: ")])
		strcat(errhd, "; ");
	    strcat(errhd, "message has embedded NULs");
	}

	if (bad_addresses)
	{
	    if (errhd[sizeof("X-Fetchmail-Warning: ")])
		strcat(errhd, "; ");
	    strcat(errhd, "SMTP listener rejected local recipient addresses: ");
	    errlen = strlen(errhd);
	    for (idp = xmit_names; idp; idp = idp->next)
		if (idp->val.num == XMIT_ANTISPAM)
		    errlen += strlen(idp->id) + 2;

	    errmsg = alloca(errlen+3);
	    (void) strcpy(errmsg, errhd);
	    for (idp = xmit_names; idp; idp = idp->next)
		if (idp->val.num == XMIT_ANTISPAM)
		{
		    strcat(errmsg, idp->id);
		    if (idp->next)
			strcat(errmsg, ", ");
		}

	}

	if (ctl->mda && !ctl->forcecr)
	    strcat(errmsg, "\n");
	else
	    strcat(errmsg, "\r\n");

	/* we may need to strip carriage returns */
	if (ctl->stripcr)
	{
	    char	*sp, *tp;

	    for (sp = tp = errmsg; *sp; sp++)
		if (*sp != '\r')
		    *tp++ =  *sp;
	    *tp = '\0';
	}

	/* ship out the error line */
	if (sinkfp)
	{
	    if (ctl->mda)
		fwrite(errmsg, sizeof(char), strlen(errmsg), sinkfp);
	    else
		SockWrite(ctl->smtp_socket, errmsg, strlen(errmsg));
	}
    }

    free_str_list(&xmit_names);

    /* issue the delimiter line */
    if (sinkfp && ctl->mda)
	fputc('\n', sinkfp);
    else if (ctl->smtp_socket != -1)
    {
	if (ctl->stripcr)
	    SockWrite(ctl->smtp_socket, "\n", 1);
	else
	    SockWrite(ctl->smtp_socket, "\r\n", 2);
    }

    return(PS_SUCCESS);
}

static int readbody(sock, ctl, forward, len, delimited)
/* read and dispose of a message body presented on sock */
struct query *ctl;	/* query control record */
int sock;		/* to which the server is connected */
int len;		/* length of message */
bool forward;		/* TRUE to forward */
bool delimited;		/* does the protocol use a message delimiter? */
{
    int	linelen;
    char buf[MSGBUFSIZE+1], *cp;

    /* pass through the text lines */
    while (delimited || len > 0)
    {
	if ((linelen = SockRead(sock, buf, sizeof(buf)-1)) == -1)
	    return(PS_SOCKET);
	set_timeout(ctl->server.timeout);

	/* write the message size dots */
	if (linelen > 0)
	{
	    sizeticker += linelen;
	    while (sizeticker >= SIZETICKER)
	    {
		if (outlevel > O_SILENT)
		    error_build(".");
		sizeticker -= SIZETICKER;
	    }
	}
	len -= linelen;

	/* fix messages that have only \n line-termination (for qmail) */
	if (ctl->forcecr)
	{
	    cp = buf + strlen(buf) - 1;
	    if (*cp == '\n' && (cp == buf || cp[-1] != '\r'))
	    {
		*cp++ = '\r';
		*cp++ = '\n';
		*cp++ = '\0';
	    }
	}

	/* check for end of message */
	if (delimited && *buf == '.')
	    if (buf[1] == '\r' && buf[2] == '\n')
		break;

	/* ship out the text line */
	if (forward)
	{
	    int	n;

	    /*
	     * SMTP byte-stuffing.  We only do this if the protocol does *not*
	     * use .<CR><LF> as EOM.  If it does, the server will already have
	     * decorated any . lines it sends back up.
	     */
	    if (!delimited && *buf == '.')
		if (sinkfp && ctl->mda)
		    fputs(".", sinkfp);
		else if (ctl->smtp_socket != -1)
		    SockWrite(ctl->smtp_socket, buf, 1);

	    /* we may need to strip carriage returns */
	    if (ctl->stripcr)
	    {
		char	*sp, *tp;

		for (sp = tp = buf; *sp; sp++)
		    if (*sp != '\r')
			*tp++ =  *sp;
		*tp = '\0';
	    }

	    n = 0;
	    if (ctl->mda)
		n = fwrite(buf, 1, strlen(buf), sinkfp);
	    else if (ctl->smtp_socket != -1)
		n = SockWrite(ctl->smtp_socket, buf, strlen(buf));

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

    return(PS_SUCCESS);
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
	error(0, -1, "kerberos error %s", (krb_get_err_text (rem)));
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
    char *msg, *cp, realname[HOSTLEN];
    void (*sigsave)();

#ifndef KERBEROS_V4
    if (ctl->server.preauthenticate == A_KERBEROS_V4)
    {
	error(0, -1, "Kerberos V4 support not linked.");
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
    sigsave = signal(SIGALRM, timeout_handler);
    set_timeout(mytimeout = ctl->server.timeout);

    if ((js = setjmp(restart)) == 1)
    {
	error(0, 0,
		"timeout after %d seconds waiting for %s.",
		ctl->server.timeout, ctl->server.names->id);
	ok = PS_ERROR;
    }
    else
    {
	char buf [POPBUFSIZE+1], *sp;
	int *msgsizes, len, num, count, new, deletions = 0;
	int sock, port, fetches;
	struct idlist *idp;

	/* execute pre-initialization command, if any */
	if (ctl->preconnect && (ok = system(ctl->preconnect)))
	{
	    sprintf(buf, "pre-connection command failed with status %d", ok);
	    error(0, 0, buf);
	    ok = PS_SYNTAX;
	    goto closeUp;
	}

	/* open a socket to the mail server */
	port = ctl->server.port ? ctl->server.port : protocol->port;
	if ((sock = SockOpen(ctl->server.names->id, port)) == -1)
	{
#ifndef EHOSTUNREACH
#define EHOSTUNREACH (-1)
#endif
	    if (outlevel == O_VERBOSE || errno != EHOSTUNREACH)
		error(0, errno, "connecting to host");
	    ok = PS_SOCKET;
	    goto closeUp;
	}

#ifdef KERBEROS_V4
	if (ctl->server.preauthenticate == A_KERBEROS_V4)
	{
	    ok = kerberos_auth(sock, ctl->server.canonical_name);
 	    if (ok != 0)
		goto cleanUp;
	    set_timeout(ctl->server.timeout);
	}
#endif /* KERBEROS_V4 */

	/* accept greeting message from mail server */
	ok = (protocol->parse_response)(sock, buf);
	if (ok != 0)
	    goto cleanUp;
	set_timeout(ctl->server.timeout);

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
	sp = (char *)NULL;	/* sacrifice to -Wall */
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
	if (protocol->getauth)
	{
	    shroud = ctl->password;
	    ok = (protocol->getauth)(sock, ctl, buf);
	    shroud = (char *)NULL;
	    if (ok == PS_ERROR)
		ok = PS_AUTHFAIL;
	    if (ok != 0)
	    {
		error(0, -1, "Authorization failure on %s@%s", 
		      ctl->remotename,
		      realname);
		goto cleanUp;
	    }
	    set_timeout(ctl->server.timeout);
	}

	ctl->errcount = fetches = 0;

	/* now iterate over each folder selected */
	for (idp = ctl->mailboxes; idp; idp = idp->next)
	{
	    if (outlevel >= O_VERBOSE)
		if (idp->next)
		    error(0, 0, "selecting folder %s");
	        else
		    error(0, 0, "selecting default folder");

	    /* compute number of messages and number of new messages waiting */
	    ok = (protocol->getrange)(sock, ctl, idp->id, &count, &new);
	    if (ok != 0)
		goto cleanUp;
	    set_timeout(ctl->server.timeout);

	    /* show user how many messages we downloaded */
	    if (idp->id)
		(void) sprintf(buf, "%s@%s:%s",
			       ctl->remotename, realname, idp->id);
	    else
		(void) sprintf(buf, "%s@%s", ctl->remotename, realname);
	    if (outlevel > O_SILENT)
		if (count == -1)		/* only used for ETRN */
		    error(0, 0, "Polling %s", buf);
		else if (count == 0)
		    error(0, 0, "No mail at %s", buf); 
		else
		{
		    if (new != -1 && (count - new) > 0)
			error(0, 0, "%d message%s (%d seen) at %s.",
			      count, count > 1 ? "s" : "", count-new, buf);
		    else
			error(0, 0, "%d message%s at %s.", 
			      count, count > 1 ? "s" : "", buf);
		}

	    /*
	     * We may need to get sizes in order to check message
	     * limits.  If we ever decide that always having accurate
	     * whole-message (as opposed to header) lengths in the
	     * progress messages is important, all we have to do is
	     * remove the `&& ctl->limit' here.
	     */
	    msgsizes = (int *)NULL;
	    if (proto->getsizes && ctl->limit > 0)
	    {
		msgsizes = (int *)alloca(sizeof(int) * count);

		ok = (proto->getsizes)(sock, count, msgsizes);
		if (ok != 0)
		    goto cleanUp;
		set_timeout(ctl->server.timeout);
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
		bool	force_retrieval;

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
		force_retrieval = !peek_capable && (ctl->errcount > 0);

		/* read, forward, and delete messages */
		for (num = 1; num <= count; num++)
		{
		    bool toolarge = (ctl->limit > 0)
			&& msgsizes && (msgsizes[num-1] > ctl->limit);
		    bool fetch_it = !toolarge 
			&& (ctl->fetchall || force_retrieval || !(protocol->is_old && (protocol->is_old)(sock,ctl,num)));
		    bool suppress_delete = FALSE;
		    bool suppress_forward = FALSE;

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
			ok = (protocol->fetch_headers)(sock, ctl, num, &len);
			if (ok != 0)
			    goto cleanUp;
			set_timeout(ctl->server.timeout);

			if (outlevel > O_SILENT)
			{
			    bool havesizes;
			    int mlen;

			    error_build("reading message %d", num);

			    if (!protocol->fetch_body)
			    {
				havesizes = TRUE;
				mlen = len;
			    }
			    else if (msgsizes)
			    {
				havesizes = TRUE;
				mlen = msgsizes[num - 1];
			    }
			    else	/* no way to know body size yet */
			    {
				havesizes = FALSE;
				mlen = len;
			    }

			    if (mlen > 0)
				error_build(" (%d %sbytes)",
					    mlen, havesizes ? "" : "header ");
			    if (outlevel == O_VERBOSE)
				error_complete(0, 0, "");
			    else
				error_build(" ");
			}

			/* 
			 * Read the message headers and ship them to the
			 * output sink.  
			 */
			ok = readheaders(sock, len, ctl, realname);
			if (ok == PS_TRANSIENT)
			    suppress_delete = TRUE;
			else if (ok == PS_REFUSED)
			    suppress_forward = TRUE;
			else if (ok)
			    goto cleanUp;
			set_timeout(ctl->server.timeout);

			/* 
			 * If we're using IMAP4 or something else that
			 * can fetch headers separately from bodies,
			 * it's time to request the body now.  This
			 * fetch may be skipped if we got an anti-spam
			 * or other PS_REFUSED error response during
			 * read_headers.
			 */
			if (protocol->fetch_body) 
			{
			    if ((ok = (protocol->trail)(sock, ctl, num)))
				goto cleanUp;
			    set_timeout(ctl->server.timeout);
			    len = 0;
			    if (!suppress_forward)
			    {
				if ((ok=(protocol->fetch_body)(sock,ctl,num,&len)))
				    goto cleanUp;
				if (!msgsizes)
				    error_build(" (%d body bytes) ", len);
				set_timeout(ctl->server.timeout);
			    }
			}

			/* process the body now */
			if (len > 0)
			{
			    ok = readbody(sock,
					  ctl,
					  !suppress_forward,
					  len,
					  protocol->delimited);
			    if (ok == PS_TRANSIENT)
				suppress_delete = TRUE;
			    else if (ok)
				goto cleanUp;
			    set_timeout(ctl->server.timeout);

			    /* tell server we got it OK and resynchronize */
			    if (protocol->trail)
			    {
				ok = (protocol->trail)(sock, ctl, num);
				if (ok != 0)
				    goto cleanUp;
				set_timeout(ctl->server.timeout);
			    }
			}

			/* end-of-message processing starts here */
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
				error(0, -1, "MDA exited abnormally or returned nonzero status");
				goto cleanUp;
			    }
			}
			else if (!suppress_forward)
			{
			    /* write message terminator */
			    if (SMTP_eom(ctl->smtp_socket) != SM_OK)
			    {
				error(0, -1, "SMTP listener refused delivery");
				ctl->errcount++;
				suppress_delete = TRUE;
			    }
			}

			fetches++;
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
			ok = (protocol->delete)(sock, ctl, num);
			if (ok != 0)
			    goto cleanUp;
			set_timeout(ctl->server.timeout);
			delete_str(&ctl->newsaved, num);
		    }
		    else if (outlevel > O_SILENT) 
			error_complete(0, 0, " not flushed");

		    /* perhaps this as many as we're ready to handle */
		    if (ctl->fetchlimit > 0 && ctl->fetchlimit <= fetches)
			goto no_error;
		}
	    }
	}

   no_error:
	set_timeout(ctl->server.timeout);
	ok = gen_transact(sock, protocol->exit_cmd);
	if (ok == 0)
	    ok = (fetches > 0) ? PS_SUCCESS : PS_NOMAIL;
	set_timeout(0);
	close(sock);
	goto closeUp;

    cleanUp:
	set_timeout(ctl->server.timeout);
	if (ok != 0 && ok != PS_SOCKET)
	    gen_transact(sock, protocol->exit_cmd);
	set_timeout(0);
	close(sock);
    }

    msg = (char *)NULL;		/* sacrifice to -Wall */
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
	error(0, -1, "%s error while fetching from %s", msg, ctl->server.names->id);

closeUp:
    signal(SIGALRM, sigsave);
    return(ok);
}

#if defined(HAVE_STDARG_H)
void gen_send(int sock, char *fmt, ... )
/* assemble command in printf(3) style and send to the server */
#else
void gen_send(sock, fmt, va_alist)
/* assemble command in printf(3) style and send to the server */
int sock;		/* socket to which server is connected */
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
    SockWrite(sock, buf, strlen(buf));

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && shroud[0] && (cp = strstr(buf, shroud)))
	{
	    char	*sp;

	    sp = cp + strlen(shroud);
	    *cp++ = '*';
	    while (*sp)
		*cp++ = *sp++;
	    *cp = '\0';
	}
	buf[strlen(buf)-2] = '\0';
	error(0, 0, "%s> %s", protocol->name, buf);
    }
}

int gen_recv(sock, buf, size)
/* get one line of input from the server */
int sock;	/* socket to which server is connected */
char *buf;	/* buffer to receive input */
int size;	/* length of buffer */
{
    if (SockRead(sock, buf, size) == -1)
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
int gen_transact(int sock, char *fmt, ... )
/* assemble command in printf(3) style, send to server, accept a response */
#else
int gen_transact(int sock, fmt, va_alist)
/* assemble command in printf(3) style, send to server, accept a response */
int sock;		/* socket to which server is connected */
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
    SockWrite(sock, buf, strlen(buf));

    if (outlevel == O_VERBOSE)
    {
	char *cp;

	if (shroud && shroud[0] && (cp = strstr(buf, shroud)))
	{
	    char	*sp;

	    sp = cp + strlen(shroud);
	    *cp++ = '*';
	    while (*sp)
		*cp++ = *sp++;
	    *cp = '\0';
	}
	buf[strlen(buf)-1] = '\0';
	error(0, 0, "%s> %s", protocol->name, buf);
    }

    /* we presume this does its own response echoing */
    ok = (protocol->parse_response)(sock, buf);
    set_timeout(mytimeout);

    return(ok);
}

/* driver.c ends here */
