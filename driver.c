/*
 * driver.c -- generic driver for mail fetch method protocols
 *
 * Copyright 1997 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"
#include  <stdio.h>
#include  <setjmp.h>
#include  <errno.h>
#include  <ctype.h>
#include  <string.h>
#ifdef HAVE_MEMORY_H
#include  <memory.h>
#endif /* HAVE_MEMORY_H */
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
#else
#ifdef _AIX
 #pragma alloca
#endif
#endif
#if defined(HAVE_SYS_ITIMER_H)
#include <sys/itimer.h>
#endif
#include  <sys/time.h>
#include  <signal.h>

#ifndef HAVE_STRFTIME /* For ctime prototype */
#include  <sys/types.h>
#include  <time.h>
#endif

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#include "mx.h"
#endif /* HAVE_GETHOSTBYNAME */

#ifdef KERBEROS_V4
#if defined (__bsdi__)
#include <des.h> /* order of includes matters */
#include <krb.h>
#define krb_get_err_text(e) (krb_err_txt[e])
#else
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__linux__)
#define krb_get_err_text(e) (krb_err_txt[e])
#include <krb.h>
#include <des.h>
#else
#include <krb.h>
#include <des.h>
#endif /* ! defined (__FreeBSD__) */
#endif /* ! defined (__bsdi__) */
#include <netinet/in.h>
#include <netdb.h>
#endif /* KERBEROS_V4 */
#ifdef KERBEROS_V5
#include <krb5.h>
#include <com_err.h>
#endif /* KEREROS_V5 */

#include  "fetchmail.h"
#include  "socket.h"
#include  "smtp.h"

/* BSD portability hack...I know, this is an ugly place to put it */
#if !defined(SIGCHLD) && defined(SIGCLD)
#define SIGCHLD	SIGCLD
#endif

#if INET6
#define	SMTP_PORT	"smtp"	/* standard SMTP service port */
#else /* INET6 */
#define	SMTP_PORT	25	/* standard SMTP service port */
#endif /* INET6 */

#ifndef strstr		/* glibc-2.1 declares this as a macro */
extern char *strstr();	/* needed on sysV68 R3V7.1. */
#endif /* strstr */

int fetchlimit;		/* how often to tear down the server connection */
int batchcount;		/* count of messages sent in current batch */
flag peek_capable;	/* can we peek for better error recovery? */
int pass;		/* how many times have we re-polled? */

static const struct method *protocol;
static jmp_buf	restart;

char tag[TAGLEN];
static int tagnum;
#define GENSYM	(sprintf(tag, "A%04d", ++tagnum % TAGMOD), tag)

static char shroud[PASSWORDLEN];	/* string to shroud in debug output */
static int mytimeout;			/* value of nonreponse timeout */
static int msglen;			/* actual message length */
static int mimemsg;			/* bitmask indicating MIME body-type */

/* use these to track what was happening when the nonresponse timer fired */
#define GENERAL_WAIT	0	/* unknown wait type */
#define SERVER_WAIT	1	/* waiting for mailserver response */
#define LISTENER_WAIT	2	/* waiting for listener initialization */
#define FORWARDING_WAIT	3	/* waiting for listener response */
static phase;

static void set_timeout(int timeleft)
/* reset the nonresponse-timeout */
{
#ifndef __EMX__
    struct itimerval ntimeout;

    ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
    ntimeout.it_value.tv_sec  = timeleft;
    ntimeout.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &ntimeout, (struct itimerval *)NULL);
#endif
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

#define MX_RETRIES	3

static int is_host_alias(const char *name, struct query *ctl)
/* determine whether name is a DNS alias of the hostname */
{
    struct hostent	*he;
    struct mxentry	*mxp, *mxrecords;

    struct hostdata *lead_server = 
	ctl->server.lead_server ? ctl->server.lead_server : &ctl->server;

    /*
     * The first two checks are optimizations that will catch a good
     * many cases.
     *
     * (1) check against the `true name' deduced from the poll label
     * and the via option (if present) at the beginning of the poll cycle.  
     * Odds are good this will either be the mailserver's FQDN or a suffix of
     * it with the mailserver's domain's default host name omitted.
     *
     * (2) Then check the rest of the `also known as'
     * cache accumulated by previous DNS checks.  This cache is primed
     * by the aka list option.
     *
     * Any of these on a mail address is definitive.  Only if the
     * name doesn't match any is it time to call the bind library.
     * If this happens odds are good we're looking at an MX name.
     */
    if (strcasecmp(lead_server->truename, name) == 0)
	return(TRUE);
    else if (str_in_list(&lead_server->akalist, name, TRUE))
	return(TRUE);
    else if (!ctl->server.dns)
	return(FALSE);

#ifndef HAVE_RES_SEARCH
    return(FALSE);
#else
    /*
     * The only code that calls the BIND library is here and in the
     * start-of-query probe with gethostbyname(3).
     *
     * We know DNS service was up at the beginning of this poll cycle.
     * If it's down, our nameserver has crashed.  We don't want to try
     * delivering the current message or anything else from this
     * mailbox until it's back up.
     */
    else if ((he = gethostbyname(name)) != (struct hostent *)NULL)
    {
	if (strcasecmp(ctl->server.truename, he->h_name) == 0)
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
		name, ctl->server.pollname);
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
	    error(0, -1,
		"nameserver failure while looking for `%s' during poll of %s.",
		name, ctl->server.pollname);
	    ctl->errcount++;
	    break;
	}
    }
    else
    {
	for (mxp = mxrecords; mxp->name; mxp++)
	    if (strcasecmp(ctl->server.truename, mxp->name) == 0)
		goto match;
	return(FALSE);
    match:;
    }

    /* add this name to relevant server's `also known as' list */
    save_str(&lead_server->akalist, name, 0);
    return(TRUE);
#endif /* HAVE_RES_SEARCH */
}

static void map_name(name, ctl, xmit_names)
/* add given name to xmit_names if it matches declared localnames */
const char *name;		/* name to map */
struct query *ctl;		/* list of permissible aliases */
struct idlist **xmit_names;	/* list of recipient names parsed out */
{
    const char	*lname;
    int sl;
    int off = 0;
    
    lname = idpair_find(&ctl->localnames, name+off);
    if (!lname && ctl->wildcard)
	lname = name+off;

    if (lname != (char *)NULL)
    {
	if (outlevel == O_VERBOSE)
	    error(0, 0, "mapped %s to local %s", name, lname);
	save_str(xmit_names, lname, XMIT_ACCEPT);
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

	for (cp = nxtaddr(hdr);
	     cp != NULL;
	     cp = nxtaddr(NULL))
	{
	    char	*atsign;

	    /*
	     * If the name of the user begins with a qmail virtual
	     * domain prefix, ignore the prefix.  Doing this here
	     * means qvirtual will work either with ordinary name
	     * mapping or with a localdomains option.
	     */
	    if (ctl->server.qvirtual)
	    {
		int sl = strlen(ctl->server.qvirtual);
 
		if (!strncasecmp(cp, ctl->server.qvirtual, sl))
		    cp += sl;
	    }

	    if ((atsign = strchr(cp, '@'))) {
		struct idlist	*idp;

		/*
		 * Does a trailing segment of the hostname match something
		 * on the localdomains list?  If so, save the whole name
		 * and keep going.
		 */
		for (idp = ctl->server.localdomains; idp; idp = idp->next) {
		    char	*rhs;

		    rhs = atsign + (strlen(atsign) - strlen(idp->id));
		    if (rhs > atsign &&
			(rhs[-1] == '.' || rhs[-1] == '@') &&
			strcasecmp(rhs, idp->id) == 0)
		    {
			if (outlevel == O_VERBOSE)
			    error(0, 0, "passed through %s matching %s", 
				  cp, idp->id);
			save_str(xmit_names, cp, XMIT_ACCEPT);
			accept_count++;
			break;
		    }
		}

		/* if we matched a local domain, idp != NULL */
		if (!idp)
		{
		    /*
		     * Check to see if the right-hand part is an alias
		     * or MX equivalent of the mailserver.  If it's
		     * not, skip this name.  If it is, we'll keep
		     * going and try to find a mapping to a client name.
		     */
		    if (!is_host_alias(atsign+1, ctl))
		    {
			save_str(xmit_names, cp, XMIT_REJECT);
			reject_count++;
			continue;
		    }
		}
		atsign[0] = '\0';
		map_name(cp, ctl, xmit_names);
	    }
	}
    }
}

static char *parse_received(struct query *ctl, char *bufp)
/* try to extract real address from the Received line */
/* If a valid Received: line is found, we return the full address in
 * a buffer which can be parsed from nxtaddr().  This is to ansure that
 * the local domain part of the address can be passed along in 
 * find_server_names() if it contains one.
 * Note: We should return a dummy header containing the address 
 * which makes nxtaddr() behave correctly. 
 */
{
    char *ok = (char *)NULL;
    static char rbuf[HOSTLEN + USERNAMELEN + 4]; 

    /*
     * Try to extract the real envelope addressee.  We look here
     * specifically for the mailserver's Received line.
     * Note: this will only work for sendmail, or an MTA that
     * shares sendmail's convention for embedding the envelope
     * address in the Received line.  Sendmail itself only
     * does this when the mail has a single recipient.
     */
    if ((ok = strstr(bufp, "by ")) && isspace(ok[-1]))
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
	if (is_host_alias(rbuf, ctl) &&
	    (ok = strstr(sp, "for ")) && 
	    isspace(ok[-1]))
	{
	    tp = rbuf;
	    sp = ok + 4;
	    *tp++ = ':';	/* Here is the hack.  This is to be friend */
	    *tp++ = ' ';	/* with nxtaddr()... */
	    if (*sp == '<')
		sp++;
	    while (*sp == '@')		/* skip routes */
		while (*sp && *sp++ != ':')
		    continue;
	    while (*sp && *sp != '>' && *sp != ';')
		if (!isspace(*sp))
		    *tp++ = *sp++;
		else
		{
		    /* uh oh -- whitespace here can't be right! */
		    ok = (char *)NULL;
		    break;
		}
	    *tp++ = '\n';
	    *tp = '\0';
	    if (strlen(rbuf) <= 3)	/* apparently nothing has been found */
		ok = NULL;
	} else
	    ok = (char *)NULL;
    }

    if (!ok)
	return(NULL);
    else
    {
	if (outlevel == O_VERBOSE) {
	    char *lf = rbuf + strlen(rbuf)-1;
	    *lf = '\0';
	    error(0, 0, "found Received address `%s'", rbuf+2);
	    *lf = '\n';
	}
	return(rbuf);
    }
}

static int smtp_open(struct query *ctl)
/* try to open a socket to the appropriate SMTP server for this query */ 
{
    /* maybe it's time to close the socket in order to force delivery */
    if (NUM_NONZERO(ctl->batchlimit) && (ctl->smtp_socket != -1) && batchcount++ == ctl->batchlimit)
    {
	close(ctl->smtp_socket);
	ctl->smtp_socket = -1;
	batchcount = 0;
    }

    /* if no socket to any SMTP host is already set up, try to open one */
    if (ctl->smtp_socket == -1) 
    {
	/* 
	 * RFC 1123 requires that the domain name in HELO address is a
	 * "valid principal domain name" for the client host. If we're
	 * running in invisible mode, violate this with malice
	 * aforethought in order to make the Received headers and
	 * logging look right.
	 *
	 * In fact this code relies on the RFC1123 requirement that the
	 * SMTP listener must accept messages even if verification of the
	 * HELO name fails (RFC1123 section 5.2.5, paragraph 2).
	 *
	 * How we compute the true mailhost name to pass to the
	 * listener doesn't affect behavior on RFC1123- violating
	 * listener that check for name match; we're going to lose
	 * on those anyway because we can never give them a name
	 * that matches the local machine fetchmail is running on.
	 * What it will affect is the listener's logging.
	 */
	struct idlist	*idp;
	char *id_me = use_invisible ? ctl->server.truename : fetchmailhost;
	int oldphase = phase;

	errno = 0;

	/*
	 * Run down the SMTP hunt list looking for a server that's up.
	 * Use both explicit hunt entries (value TRUE) and implicit 
	 * (default) ones (value FALSE).
	 */
	oldphase = phase;
	phase = LISTENER_WAIT;

	set_timeout(ctl->server.timeout);
	for (idp = ctl->smtphunt; idp; idp = idp->next)
	{
	    char	*cp, *parsed_host = alloca(strlen(idp->id) + 1);
#ifdef INET6 
	    char	*portnum = SMTP_PORT;
#else
	    int		portnum = SMTP_PORT;
#endif /* INET6 */

	    ctl->smtphost = idp->id;  /* remember last host tried. */

	    strcpy(parsed_host, idp->id);
	    if ((cp = strrchr(parsed_host, '/')))
	    {
		*cp++ = 0;
#ifdef INET6 
		portnum = cp;
#else
		portnum = atoi(cp);
#endif /* INET6 */
	    }

	    if ((ctl->smtp_socket = SockOpen(parsed_host,portnum,NULL)) == -1)
		continue;

	    /* first, probe for ESMTP */
	    if (SMTP_ok(ctl->smtp_socket) == SM_OK &&
		    SMTP_ehlo(ctl->smtp_socket, id_me,
			  &ctl->server.esmtp_options) == SM_OK)
	       break;  /* success */

	    /*
	     * RFC 1869 warns that some listeners hang up on a failed EHLO,
	     * so it's safest not to assume the socket will still be good.
	     */
	    close(ctl->smtp_socket);
	    ctl->smtp_socket = -1;

	    /* if opening for ESMTP failed, try SMTP */
	    if ((ctl->smtp_socket = SockOpen(parsed_host,portnum,NULL)) == -1)
		continue;

	    if (SMTP_ok(ctl->smtp_socket) == SM_OK && 
		    SMTP_helo(ctl->smtp_socket, id_me) == SM_OK)
		break;  /* success */

	    close(ctl->smtp_socket);
	    ctl->smtp_socket = -1;
	}
	set_timeout(0);
	phase = oldphase;
    }

    if (outlevel >= O_VERBOSE && ctl->smtp_socket != -1)
	error(0, 0, "forwarding to %s", ctl->smtphost);

    return(ctl->smtp_socket);
}

/* these are shared by stuffline, readheaders and readbody */
static FILE *sinkfp;
static RETSIGTYPE (*sigchld)();
static int sizeticker;

static int stuffline(struct query *ctl, char *buf)
/* ship a line to the given control block's output sink (SMTP server or MDA) */
{
    int	n, oldphase;
    char *last;

    /* The line may contain NUL characters. Find the last char to use
     * -- the real line termination is the sequence "\n\0".
     */
    last = buf;
    while ((last += strlen(last)) && (last[-1] != '\n'))
        last++;

    /* fix message lines that have only \n termination (for qmail) */
    if (ctl->forcecr)
    {
        if (last - 1 == buf || last[-2] != '\r')
	{
	    last[-1] = '\r';
	    *last++  = '\n';
	    *last    = '\0';
	}
    }

    oldphase = phase;
    phase = FORWARDING_WAIT;

    /*
     * SMTP byte-stuffing.  We only do this if the protocol does *not*
     * use .<CR><LF> as EOM.  If it does, the server will already have
     * decorated any . lines it sends back up.
     */
    if (*buf == '.')
	if (protocol->delimited)	/* server has already byte-stuffed */
	{
	    if (ctl->mda)
		++buf;
	    else
		/* writing to SMTP, leave the byte-stuffing in place */;
	}
        else /* if (!protocol->delimited)	-- not byte-stuffed already */
	{
	    if (!ctl->mda)
		SockWrite(ctl->smtp_socket, buf, 1);	/* byte-stuff it */
	    else
		/* leave it alone */;
	}

    /* we may need to strip carriage returns */
    if (ctl->stripcr)
    {
	char	*sp, *tp;

	for (sp = tp = buf; sp < last; sp++)
	    if (*sp != '\r')
		*tp++ =  *sp;
	*tp = '\0';
        last = tp;
    }

    n = 0;
    if (ctl->mda)
	n = fwrite(buf, 1, last - buf, sinkfp);
    else if (ctl->smtp_socket != -1)
	n = SockWrite(ctl->smtp_socket, buf, last - buf);

    phase = oldphase;

    return(n);
}

#define EMPTYLINE(s)	((s)[0] == '\r' && (s)[1] == '\n' && (s)[2] == '\0')

static int readheaders(sock, fetchlen, reallen, ctl, num)
/* read message headers and ship to SMTP or MDA */
int sock;		/* to which the server is connected */
long fetchlen;		/* length of message according to fetch response */
long reallen;		/* length of message according to getsizes */
struct query *ctl;	/* query control record */
int num;		/* index of message */
{
    struct addrblk
    {
	int		offset;
	struct addrblk	*next;
    };
    struct addrblk	*to_addrchain = NULL;
    struct addrblk	**to_chainptr = &to_addrchain;
    struct addrblk	*resent_to_addrchain = NULL;
    struct addrblk	**resent_to_chainptr = &resent_to_addrchain;

    char		buf[MSGBUFSIZE+1];
    char		return_path[HOSTLEN + USERNAMELEN + 4]; 
    int			from_offs, reply_to_offs, resent_from_offs;
    int			app_from_offs, sender_offs, resent_sender_offs;
    int			env_offs;
    char		*headers, *received_for, *destaddr, *rcv, *cp;
    int 		n, linelen, oldlen, ch, remaining, skipcount;
    struct idlist 	*idp, *xmit_names;
    flag		good_addresses, bad_addresses, has_nuls;
    flag		no_local_matches = FALSE;
    flag		headers_ok;
    int			olderrs;

    sizeticker = 0;
    has_nuls = headers_ok = FALSE;
    return_path[0] = '\0';
    olderrs = ctl->errcount;

    /* read message headers */
    headers = received_for = NULL;
    from_offs = reply_to_offs = resent_from_offs = app_from_offs = 
	sender_offs = resent_sender_offs = env_offs = -1;
    oldlen = 0;
    msglen = 0;
    skipcount = 0;
    mimemsg = 0;

    for (remaining = fetchlen; remaining > 0 || protocol->delimited; remaining -= linelen)
    {
	char *line;

	line = xmalloc(sizeof(buf));
	linelen = 0;
	line[0] = '\0';
	do {
	    set_timeout(ctl->server.timeout);
	    if ((n = SockRead(sock, buf, sizeof(buf)-1)) == -1) {
		set_timeout(0);
		free(line);
		free(headers);
		return(PS_SOCKET);
	    }
	    set_timeout(0);
	    linelen += n;
	    msglen += n;

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


	    line = (char *) realloc(line, strlen(line) + strlen(buf) +1);

	    strcat(line, buf);

	    /* check for end of headers */
	    if (EMPTYLINE(line))
	    {
		headers_ok = TRUE;
		has_nuls = (linelen != strlen(line));
		free(line);
		goto process_headers;
	    }

	    /*
	     * Check for end of message immediately.  If one of your folders
	     * has been mangled, the delimiter may occur directly after the
	     * header.
	     */
	    if (protocol->delimited && line[0] == '.' && EMPTYLINE(line+1))
	    {
		free(line);
		has_nuls = (linelen != strlen(line));
		goto process_headers;
	    }
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

	/* we see an ordinary (non-header, non-message-delimiter line */
	has_nuls = (linelen != strlen(line));

	/*
	 * The University of Washington IMAP server (the reference
	 * implementation of IMAP4 written by Mark Crispin) relies
	 * on being able to keep base-UID information in a special
	 * message at the head of the mailbox.  This message should
	 * neither be deleted nor forwarded.
	 */
#ifdef POP2_ENABLE
	/*
	 * We disable this check under POP2 because there's no way to
	 * prevent deletion of the message.  So at least we ought to 
	 * forward it to the user so he or she will have some clue
	 * that things have gone awry.
	 */
	if (protocol->port != 109)
#endif /* POP2_ENABLE */
	    if (num == 1 && !strncasecmp(line, "X-IMAP:", 7)) {
		free(line);
		free(headers);
		return(PS_RETAINED);
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
	 * If we see a Status line, it may have been inserted by an MUA
	 * on the mail host, or it may have been inserted by the server
	 * program after the headers in the transaction stream.  This
	 * can actually hose some new-mail notifiers such as xbuffy,
	 * which assumes any Status line came from a *local* MDA and
	 * therefore indicates that the message has been seen.
	 *
	 * Some buggy POP servers (including at least the 3.3(20)
	 * version of the one distributed with IMAP) insert empty
	 * Status lines in the transaction stream; we'll chuck those
	 * unconditionally.  Nonempty ones get chucked if the user
	 * turns on the dropstatus flag.
	 */
	{
	    char	*cp;
	    if (!strncasecmp(line, "Status:", 7))
		cp = line + 7;
	    else if (!strncasecmp(line, "X-Mozilla-Status:", 17))
		cp = line + 17;
	    else
		cp = NULL;
	    if (cp) {
		while (*cp && isspace(*cp)) cp++;
		if (!*cp || ctl->dropstatus)
		{
		    free(line);
		    continue;
		}
	    }
	}

	if (ctl->rewrite)
	    line = reply_hack(line, ctl->server.truename);

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
	 *
	 * We do *not* want to ignore empty Return-Path headers.  These should
	 * be passed through as a way of indicating that a message should
	 * not trigger bounces if delivery fails.  What we *do* need to do is
	 * make sure we never try to rewrite such a blank Return-Path.  We
	 * handle this with a check for <> in the rewrite logic.
	 */
	if (!strncasecmp("Return-Path:", line, 12) && (cp = nxtaddr(line)))
	{
	    strcpy(return_path, cp);
	    if (!ctl->mda) {
		free(line);
		continue;
	    }
	}

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
	    if (headers == NULL) {
		free(line);
		return(PS_IOERR);
	    }
	    strcpy(headers + oldlen, line);
	    free(line);
	    line = headers + oldlen;
	    oldlen = newlen;
	}

	if (!strncasecmp("From:", line, 5))
	    from_offs = (line - headers);
	else if (!strncasecmp("Reply-To:", line, 9))
	    reply_to_offs = (line - headers);
	else if (!strncasecmp("Resent-From:", line, 12))
	    resent_from_offs = (line - headers);
	else if (!strncasecmp("Apparently-From:", line, 16))
	    app_from_offs = (line - headers);
	else if (!strncasecmp("Sender:", line, 7))
	    sender_offs = (line - headers);
	else if (!strncasecmp("Resent_Sender:", line, 14))
	    resent_sender_offs = (line - headers);

 	else if (!strncasecmp("Message-Id:", buf, 11))
	{
	    if (ctl->server.uidl)
 	    {
	        char id[IDLEN+1];

		buf[IDLEN+12] = 0;		/* prevent stack overflow */
 		sscanf(buf+12, "%s", id);
 	        if (!str_find( &ctl->newsaved, num))
		{
 		    struct idlist *new = save_str(&ctl->newsaved,id,UID_SEEN);
		    new->val.status.num = num;
		}
 	    }
 	}

	else if (!MULTIDROP(ctl))
	    continue;

	else if (!strncasecmp("To:", line, 3)
			|| !strncasecmp("Cc:", line, 3)
			|| !strncasecmp("Bcc:", line, 4)
			|| !strncasecmp("Apparently-To:", line, 14))
	{
	    *to_chainptr = xmalloc(sizeof(struct addrblk));
	    (*to_chainptr)->offset = (line - headers);
	    to_chainptr = &(*to_chainptr)->next; 
	    *to_chainptr = NULL;
	}

	else if (!strncasecmp("Resent-To:", line, 10)
			|| !strncasecmp("Resent-Cc:", line, 10)
			|| !strncasecmp("Resent-Bcc:", line, 11))
	{
	    *resent_to_chainptr = xmalloc(sizeof(struct addrblk));
	    (*resent_to_chainptr)->offset = (line - headers);
	    resent_to_chainptr = &(*resent_to_chainptr)->next; 
	    *resent_to_chainptr = NULL;
	}

	else if (ctl->server.envelope != STRING_DISABLED)
	{
	    if (ctl->server.envelope 
			&& strcasecmp(ctl->server.envelope, "Received"))
	    {
		if (env_offs == -1 && !strncasecmp(ctl->server.envelope,
						line,
						strlen(ctl->server.envelope)))
		{				
		    if (skipcount++ != ctl->server.envskip)
			continue;
		    env_offs = (line - headers);
		}    
	    }
	    else if (!received_for && !strncasecmp("Received:", line, 9))
	    {
		if (skipcount++ != ctl->server.envskip)
		    continue;
		received_for = parse_received(ctl, line);
	    }
	}
    }

 process_headers:
    /*
     * We want to detect this early in case there are so few headers that the
     * dispatch logic barfs.
     */
    if (!headers_ok)
    {
	if (outlevel > O_SILENT)
	    error(0,0,"message delimiter found while scanning headers");
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
#ifdef HAVE_SNPRINTF
	snprintf(buf, sizeof(buf),
#else
	sprintf(buf, 
#endif /* HAVE_SNPRINTF */
	"From: <FETCHMAIL-DAEMON@%s>\r\nTo: %s@localhost\r\nSubject: Headerless mail from %s's mailbox on %s\r\n",
		fetchmailhost, user, ctl->remotename, ctl->server.truename);
	headers = xstrdup(buf);
    }

    /*
     * We can now process message headers before reading the text.
     * In fact we have to, as this will tell us where to forward to.
     */

    /* Decode MIME encoded headers. We MUST do this before
     * looking at the Content-Type / Content-Transfer-Encoding
     * headers (RFC 2046).
     */
    if (ctl->mimedecode) {
	UnMimeHeader(headers);
    }
    /* Check for MIME headers indicating possible 8-bit data */
    mimemsg = MimeBodyType(headers, ctl->mimedecode);

    /*
     * If there is a Return-Path address on the message, this was
     * almost certainly the MAIL FROM address given the originating
     * sendmail.  This is the best thing to use for logging the
     * message origin (it sets up the right behavior for bounces and
     * mailing lists).  Otherwise, fall down to the next available 
     * envelope address (which is the most probable real sender).
     * *** The order is important! ***
     * This is especially useful when receiving mailing list
     * messages in multidrop mode.  if a local address doesn't
     * exist, the bounce message won't be returned blindly to the 
     * author or to the list itself but rather to the list manager
     * (ex: specified by "Sender:") wich is less anoying.  This is
     * true for most mailing list packages.
     */
    if( !return_path[0] ){
	char *ap = NULL;
	if (resent_sender_offs >= 0 && (ap = nxtaddr(headers + resent_sender_offs)));
	else if (sender_offs >= 0 && (ap = nxtaddr(headers + sender_offs)));
	else if (resent_from_offs >= 0 && (ap = nxtaddr(headers + resent_from_offs)));
	else if (from_offs >= 0 && (ap = nxtaddr(headers + from_offs)));
	else if (reply_to_offs >= 0 && (ap = nxtaddr(headers + reply_to_offs)));
	else if (app_from_offs >= 0 && (ap = nxtaddr(headers + app_from_offs)));
	if (ap) strcpy( return_path, ap );
    }

    /* cons up a list of local recipients */
    xmit_names = (struct idlist *)NULL;
    bad_addresses = good_addresses = accept_count = reject_count = 0;
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
	     * We use find_server_names() to let local 
	     * hostnames go through.
	     */
	    find_server_names(received_for, ctl, &xmit_names);
	else {
	    /*
	     * We haven't extracted the envelope address.
	     * So check all the "Resent-To" header addresses if 
	     * they exist.  If and only if they don't, consider
	     * the "To" adresses.
	     */
	    register struct addrblk *nextptr;
	    if (resent_to_addrchain) {
		/* delete the "To" chain and substitute it 
		 * with the "Resent-To" list 
		 */
		while (to_addrchain) {
		    nextptr = to_addrchain->next;
		    free(to_addrchain);
		    to_addrchain = nextptr;
		}
		to_addrchain = resent_to_addrchain;
		resent_to_addrchain = NULL;
	    }
	    /* now look for remaining adresses */
	    while (to_addrchain) {
		find_server_names(headers+to_addrchain->offset, ctl, &xmit_names);
		nextptr = to_addrchain->next;
		free(to_addrchain);
		to_addrchain = nextptr;
	    }
	}
	if (!accept_count)
	{
	    no_local_matches = TRUE;
	    save_str(&xmit_names, user, XMIT_ACCEPT);
	    if (outlevel == O_VERBOSE)
		error(0, 0, 
		      "no local matches, forwarding to %s",
		      user);
	}
    }
    else	/* it's a single-drop box, use first localname */
	save_str(&xmit_names, ctl->localnames->id, XMIT_ACCEPT);


    /*
     * Time to either address the message or decide we can't deliver it yet.
     */
    if (ctl->errcount > olderrs)	/* there were DNS errors above */
    {
	if (outlevel == O_VERBOSE)
	    error(0,0, "forwarding and deletion suppressed due to DNS errors");
	free(headers);
	free_str_list(&xmit_names);
	return(PS_TRANSIENT);
    }
    else if (ctl->mda)		/* we have a declared MDA */
    {
	int	length = 0;
	char	*names, *before, *after;

	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.status.mark == XMIT_ACCEPT)
		good_addresses++;

	length = strlen(ctl->mda) + 1;
	before = xstrdup(ctl->mda);

	/* sub user addresses for %T (or %s for backward compatibility) */
	cp = (char *)NULL;
	if (strstr(before, "%s") || (cp = strstr(before, "%T")))
	{
	    char	*sp;

	    if (cp && cp[1] == 'T')
		cp[1] = 's';

	    /* \177 had better be out-of-band for MDA commands */
	    for (sp = before; *sp; sp++)
		if (*sp == '%' && sp[1] != 's' && sp[1] != 'T')
		    *sp = '\177';

	    /*
	     * We go through this in order to be able to handle very
	     * long lists of users and (re)implement %s.
	     */
	    for (idp = xmit_names; idp; idp = idp->next)
		if (idp->val.status.mark == XMIT_ACCEPT)
		    length += (strlen(idp->id) + 1);

	    names = (char *)xmalloc(++length);
	    names[0] = '\0';
	    for (idp = xmit_names; idp; idp = idp->next)
		if (idp->val.status.mark == XMIT_ACCEPT)
		{
		    strcat(names, idp->id);
		    strcat(names, " ");
		}
	    after = (char *)xmalloc(length);
#ifdef SNPRINTF
	    snprintf(after, length, before, names);
#else
	    sprintf(after, before, names);
#endif /* SNPRINTF */
	    free(names);
	    free(before);
	    before = after;

	    for (sp = before; *sp; sp++)
		if (*sp == '\177')
		    *sp = '%';
	}

	/* substitute From address for %F */
	if ((cp = strstr(before, "%F")))
	{
	    char *from = return_path;
	    char	*sp;

	    /* \177 had better be out-of-band for MDA commands */
	    for (sp = before; *sp; sp++)
		if (*sp == '%' && sp[1] != 'F')
		    *sp = '\177';

	    length += strlen(from);
	    after = (char *)xmalloc(length);
	    cp[1] = 's';
#ifdef SNPRINTF
	    snprintf(after, length, before, from);
#else
	    sprintf(after, before, from);
#endif /* SNPRINTF */
	    free(before);
	    before = after;

	    for (sp = before; *sp; sp++)
		if (*sp == '\177')
		    *sp = '%';
	}

	if (outlevel == O_VERBOSE)
	    error(0, 0, "about to deliver with: %s", before);

#ifdef HAVE_SETEUID
	/*
	 * Arrange to run with user's permissions if we're root.
	 * This will initialize the ownership of any files the
	 * MDA creates properly.  (The seteuid call is available
	 * under all BSDs and Linux)
	 */
	seteuid(ctl->uid);
#endif /* HAVE_SETEUID */

	sinkfp = popen(before, "w");
	free(before);

#ifdef HAVE_SETEUID
	/* this will fail quietly if we didn't start as root */
	seteuid(0);
#endif /* HAVE_SETEUID */

	if (!sinkfp)
	{
	    error(0, 0, "MDA open failed");
	    free(headers);
	    free_str_list(&xmit_names);
	    return(PS_IOERR);
	}

	sigchld = signal(SIGCHLD, SIG_DFL);
    }
    else
    {
	char	*ap, options[MSGBUFSIZE], addr[128];

	/* build a connection to the SMTP listener */
	if ((smtp_open(ctl) == -1))
	{
	    error(0, errno, "SMTP connect to %s failed",
		  ctl->smtphost ? ctl->smtphost : "localhost");
	    free(headers);
	    free_str_list(&xmit_names);
	    return(PS_SMTP);
	}

	/*
	 * Compute ESMTP options.
	 */
	options[0] = '\0';
	if (ctl->server.esmtp_options & ESMTP_8BITMIME) {
             if (ctl->pass8bits || (mimemsg & MSG_IS_8BIT))
		strcpy(options, " BODY=8BITMIME");
             else if (mimemsg & MSG_IS_7BIT)
		strcpy(options, " BODY=7BIT");
        }

	if ((ctl->server.esmtp_options & ESMTP_SIZE) && reallen > 0)
	    sprintf(options + strlen(options), " SIZE=%ld", reallen);

	/*
	 * Try to get the SMTP listener to take the Return-Path
	 * address as MAIL FROM .  If it won't, fall back on the
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
	 *
	 * None of these error conditions generates bouncemail.  Comments
	 * below explain for each case why this is so.
	 */
	ap = (return_path[0]) ? return_path : user;
	if (SMTP_from(ctl->smtp_socket, ap, options) != SM_OK)
	{
	    int smtperr = atoi(smtp_response);

	    if (smtperr == ctl->antispam)
	    {
		/*
		 * SMTP listener explicitly refuses to deliver mail
		 * coming from this address, probably due to an
		 * anti-spam domain exclusion.  Respect this.  Don't
		 * try to ship the message, and don't prevent it from
		 * being deleted.  Typical values:
		 *
		 * 571 = sendmail's "unsolicited email refused"
		 * 501 = exim's old antispam response
		 * 550 = exim's new antispam response (temporary)
		 *
		 * We don't send bouncemail on antispam failures because
		 * we don't want the scumbags to know the address is even
		 * valid.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		free(headers);
		free_str_list(&xmit_names);
		return(PS_REFUSED);
	    }

	    /*
	     * Suppress error message only if the response specifically 
	     * meant `excluded for policy reasons'.  We *should* see
	     * an error when the return code is less specific.
	     */
	    if (smtperr >= 400)
		error(0, -1, "SMTP error: %s", smtp_response);

	    switch (smtperr)
	    {
	    case 452: /* insufficient system storage */
		/*
		 * Temporary out-of-queue-space condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and suppress deletion so it can be retried on
		 * a future retrieval cycle. 
		 *
		 * Bouncemail *might* be appropriate here as a delay
		 * notification.  But it's not really necessary because
		 * this is not an actual failure, we're very likely to be
		 * able to recover on the next cycle.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		free(headers);
		free_str_list(&xmit_names);
		return(PS_TRANSIENT);

	    case 552: /* message exceeds fixed maximum message size */
	    case 553: /* invalid sending domain */
		/*
		 * Permanent no-go condition on the
		 * ESMTP server.  Don't try to ship the message, 
		 * and allow it to be deleted.
		 *
		 * Bouncemail would be appropriate for 552, but in these 
		 * latter days 553 usually means a spammer is trying to
		 * cover his tracks.  We'd rather deny the scumbags any
		 * feedback that the address is valid.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		free(headers);
		free_str_list(&xmit_names);
		return(PS_REFUSED);

	    default:	/* retry with invoking user's address */
		if (SMTP_from(ctl->smtp_socket, user, options) != SM_OK)
		{
		    error(0, -1, "SMTP error: %s", smtp_response);
		    free(headers);
		    free_str_list(&xmit_names);
		    return(PS_SMTP);	/* should never happen */
		}
	    }
	}

	/*
	 * Now list the recipient addressees
	 *
	 * RFC 1123 requires that the domain name part of the
	 * RCPT TO address be "canonicalized", that is a FQDN
	 * or MX but not a CNAME.  Some listeners (like exim)
	 * enforce this.
	 */
	destaddr = ctl->smtpaddress ? ctl->smtpaddress : ( ctl->smtphost ? ctl->smtphost : "localhost");
	
	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.status.mark == XMIT_ACCEPT)
	    {
		if (strchr(idp->id, '@'))
		    strcpy(addr, idp->id);
		else
#ifdef HAVE_SNPRINTF
		    snprintf(addr, sizeof(addr)-1, "%s@%s", idp->id, destaddr);
#else
		    sprintf(addr, "%s@%s", idp->id, destaddr);
#endif /* HAVE_SNPRINTF */

		if (SMTP_rcpt(ctl->smtp_socket, addr) == SM_OK)
		    good_addresses++;
		else
		{
		    bad_addresses++;
		    idp->val.status.mark = XMIT_ANTISPAM;
		    error(0, 0, 
			  "SMTP listener doesn't like recipient address `%s'",
			  addr);
		}
	    }
	if (!good_addresses)
	{
#ifdef HAVE_SNPRINTF
	    snprintf(addr, sizeof(addr)-1, "%s@%s", user, destaddr);
#else
	    sprintf(addr, "%s@%s", user, destaddr);
#endif /* HAVE_SNPRINTF */

	    if (SMTP_rcpt(ctl->smtp_socket, addr) != SM_OK)
	    {
		error(0, 0, "can't even send to calling user!");
		free(headers);
		free_str_list(&xmit_names);
		return(PS_SMTP);
	    }
	}

	/* tell it we're ready to send data */
	SMTP_data(ctl->smtp_socket);
    }

    n = 0;
    /*
     * Some server/sendmail combinations cause problems when our
     * synthetic Received line is before the From header.  Cope
     * with this...
     */
    if ((rcv = strstr(headers, "Received:")) == (char *)NULL)
	rcv = headers;
    if (rcv > headers)
    {
	*rcv = '\0';
	n = stuffline(ctl, headers);
	*rcv = 'R';
    }
    if (!use_invisible && n != -1)
    {
	/* utter any per-message Received information we need here */
	sprintf(buf, "Received: from %s\n", ctl->server.truename);
	n = stuffline(ctl, buf);
	if (n != -1)
	{
	    /*
	     * We used to include ctl->remotename in this log line,
	     * but this can be secure information that would be bad
	     * to reveal.
	     */
	    sprintf(buf, "\tby %s (fetchmail-%s %s)\n",
		    fetchmailhost, 
		    RELEASE_ID,
		    protocol->name);
	    n = stuffline(ctl, buf);
	    if (n != -1)
	    {
		time_t	now;

		buf[0] = '\t';
		if (good_addresses == 0)
		{
		    sprintf(buf+1, 
			    "for <%s@%s> (by default); ",
			    user, destaddr);
		}
		else if (good_addresses == 1)
		{
		    for (idp = xmit_names; idp; idp = idp->next)
			if (idp->val.status.mark == XMIT_ACCEPT)
			    break;	/* only report first address */
		    if (strchr(idp->id, '@'))
			sprintf(buf+1, "for <%s>", idp->id);
		    else
			sprintf(buf+1, "for <%s/%s>", idp->id, destaddr);
		    sprintf(buf+strlen(buf), " (%s); ",
			    MULTIDROP(ctl) ? "multi-drop" : "single-drop");
		}
		else
		    buf[1] = '\0';

		time(&now);
#ifdef HAVE_STRFTIME
		/*
		 * Conform to RFC822.  This is typically going to emit
		 * a three-letter timezone for %Z, which is going to
		 * be marked "obsolete syntax" in 822bis.  Note that we
		 * generate a 4-digit year here.
		 */
		strftime(buf + strlen(buf), sizeof(buf) - strlen(buf), 
			 "%a, %d %b %Y %H:%M:%S %Z\n", localtime(&now));
#else
		/*
		 * This is really just a portability fallback, as the
		 * date format ctime(3) emits is not RFC822
		 * conformant.
		 */
		strcat(buf, ctime(&now));
#endif /* HAVE_STRFTIME */
		n = stuffline(ctl, buf);
	    }
	}
    }

    if (n != -1)
	n = stuffline(ctl, rcv);	/* ship out rest of headers */

    if (n == -1)
    {
	error(0, errno, "writing RFC822 headers");
	if (ctl->mda)
	{
	    if (sinkfp)
		pclose(sinkfp);
	    signal(SIGCHLD, sigchld);
	}
	free(headers);
	free_str_list(&xmit_names);
	return(PS_IOERR);
    }
    else if (outlevel == O_VERBOSE)
	fputs("#", stderr);

    /* write error notifications */
    if (no_local_matches || has_nuls || bad_addresses)
    {
	int	errlen = 0;
	char	errhd[USERNAMELEN + POPBUFSIZE], *errmsg;

	errmsg = errhd;
	(void) strcpy(errhd, "X-Fetchmail-Warning: ");
	if (no_local_matches)
	{
	    if (reject_count != 1)
		strcat(errhd, "no recipient addresses matched declared local names");
	    else
	    {
		for (idp = xmit_names; idp; idp = idp->next)
		    if (idp->val.status.mark == XMIT_REJECT)
			break;
		sprintf(errhd+strlen(errhd), "recipient address %s didn't match any local name", idp->id);
	    }
	}

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
		if (idp->val.status.mark == XMIT_ANTISPAM)
		    errlen += strlen(idp->id) + 2;

	    errmsg = alloca(errlen+3);
	    (void) strcpy(errmsg, errhd);
	    for (idp = xmit_names; idp; idp = idp->next)
		if (idp->val.status.mark == XMIT_ANTISPAM)
		{
		    strcat(errmsg, idp->id);
		    if (idp->next)
			strcat(errmsg, ", ");
		}

	}

	strcat(errmsg, "\n");

	/* ship out the error line */
	if (sinkfp)
	    stuffline(ctl, errmsg);
    }

    /* issue the delimiter line */
    cp = buf;
    *cp++ = '\r';
    *cp++ = '\n';
    *cp++ = '\0';
    stuffline(ctl, buf);

    free(headers);
    free_str_list(&xmit_names);
    return(headers_ok ? PS_SUCCESS : PS_TRUNCATED);
}

static int readbody(sock, ctl, forward, len)
/* read and dispose of a message body presented on sock */
struct query *ctl;	/* query control record */
int sock;		/* to which the server is connected */
int len;		/* length of message */
flag forward;		/* TRUE to forward */
{
    int	linelen;
    unsigned char buf[MSGBUFSIZE+1];
    unsigned char *inbufp = buf;
    flag issoftline = FALSE;

    /* pass through the text lines */
    while (protocol->delimited || len > 0)
    {
	set_timeout(ctl->server.timeout);
	if ((linelen = SockRead(sock, inbufp, sizeof(buf)-1-(inbufp-buf)))==-1)
	{
	    set_timeout(0);
	    if (ctl->mda)
	    {
		if (sinkfp)
		    pclose(sinkfp);
		signal(SIGCHLD, sigchld);
	    }
	    return(PS_SOCKET);
	}
	set_timeout(0);

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

	/* check for end of message */
	if (protocol->delimited && *inbufp == '.')
	    if (inbufp[1] == '\r' && inbufp[2] == '\n' && inbufp[3] == '\0')
		break;
	    else if (inbufp[1] == '\n' && inbufp[2] == '\0')
		break;
	    else
		msglen--;	/* subtract the size of the dot escape */

	msglen += linelen;

	if (ctl->mimedecode && (mimemsg & MSG_NEEDS_DECODE)) {
	    issoftline = UnMimeBodyline(&inbufp, (protocol->delimited && issoftline));
	    if (issoftline && (sizeof(buf)-1-(inbufp-buf) < 200))
	    {
		/*
		 * Soft linebreak, but less than 200 bytes left in
		 * input buffer. Rather than doing a buffer overrun,
		 * ignore the soft linebreak, NL-terminate data and
		 * deliver what we have now.
		 * (Who writes lines longer than 2K anyway?)
		 */
		*inbufp = '\n'; *(inbufp+1) = '\0';
		issoftline = 0;
	    }
	}

	/* ship out the text line */
	if (forward && (!issoftline))
	{
	    int	n = stuffline(ctl, buf);
	    inbufp = buf;

	    if (n < 0)
	    {
		error(0, errno, "writing message text");
		if (ctl->mda)
		{
		    if (sinkfp)
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
#ifdef __FreeBSD__
char *canonical;	/* server name */
#else
const char *canonical;	/* server name */
#endif
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
	return (PS_AUTHFAIL);
    }
    return (0);
}
#endif /* KERBEROS_V4 */

#ifdef KERBEROS_V5
int
kerberos5_auth(socket, canonical)
/* authernticate to the server host using Kerberos V5 */
int socket;             /* socket to server host */
const char *canonical;  /* server name */
{
    krb5_error_code retval;
    krb5_context context;
    krb5_ccache ccdef;
    krb5_principal client = NULL, server = NULL;
    krb5_error *err_ret = NULL;

    krb5_auth_context auth_context = NULL;

    krb5_init_context(&context);
    krb5_init_ets(context);
    krb5_auth_con_init(context, &auth_context);

    if (retval = krb5_cc_default(context, &ccdef)) {
        error(0, 0, "krb5_cc_default: %s", error_message(retval));
        return(PS_ERROR);
    }

    if (retval = krb5_cc_get_principal(context, ccdef, &client)) {
        error(0, 0, "krb5_cc_get_principal: %s", error_message(retval));
        return(PS_ERROR);
    }

    if (retval = krb5_sname_to_principal(context, canonical, "pop",
           KRB5_NT_UNKNOWN,
           &server)) {
        error(0, 0, "krb5_sname_to_principal: %s", error_message(retval));
        return(PS_ERROR);
    }

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &socket,
         "KPOPV1.0", client, server,
         AP_OPTS_MUTUAL_REQUIRED,
         NULL,  /* no data to checksum */
         0,   /* no creds, use ccache instead */
         ccdef,
         &err_ret, 0,

         NULL); /* don't need reply */

    krb5_free_principal(context, server);
    krb5_free_principal(context, client);
    krb5_auth_con_free(context, auth_context);

    if (retval) {
      if (err_ret && err_ret->text.length) {
          error(0, 0, "krb5_sendauth: %s [server says '%*s'] ",
            error_message(retval),
            err_ret->text.length,
            err_ret->text.data);
          krb5_free_error(context, err_ret);
      } else
          error(0, 0, "krb5_sendauth: %s", error_message(retval));
      return(PS_ERROR);
    }

    return 0;
}
#endif /* KERBEROS_V5 */

int do_protocol(ctl, proto)
/* retrieve messages from server using given protocol method table */
struct query *ctl;		/* parsed options with merged-in defaults */
const struct method *proto;	/* protocol method table */
{
    int ok, js, sock = -1;
    char *msg;
    void (*sigsave)();

#ifndef KERBEROS_V4
    if (ctl->server.preauthenticate == A_KERBEROS_V4)
    {
	error(0, -1, "Kerberos V4 support not linked.");
	return(PS_ERROR);
    }
#endif /* KERBEROS_V4 */

#ifndef KERBEROS_V5
    if (ctl->server.preauthenticate == A_KERBEROS_V5)
    {
	error(0, -1, "Kerberos V5 support not linked.");
	return(PS_ERROR);
    }
#endif /* KERBEROS_V5 */

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
    if (!proto->getsizes && NUM_SPECIFIED(ctl->limit))
    {
	error(0, 0,
		"Option --limit is not supported with %s",
		proto->name);
	return(PS_SYNTAX);
    }

    protocol = proto;
    pass = 0;
    tagnum = 0;
    tag[0] = '\0';	/* nuke any tag hanging out from previous query */
    ok = 0;

    /* set up the server-nonresponse timeout */
    sigsave = signal(SIGALRM, timeout_handler);
    mytimeout = ctl->server.timeout;

    if ((js = setjmp(restart)) == 1)
    {
	if (phase == SERVER_WAIT)
	    error(0, 0,
		  "timeout after %d seconds waiting for server %s.",
		  ctl->server.timeout, ctl->server.pollname);
	else if (phase == FORWARDING_WAIT)
	    error(0, 0,
		  "timeout after %d seconds waiting for %s.",
		  ctl->server.timeout,
		  ctl->mda ? "MDA" : "SMTP");
	else if (phase == LISTENER_WAIT)
	    error(0, 0,
		  "timeout after %d seconds waiting for listener to respond.");
	else
	    error(0, 0, "timeout after %d seconds.", ctl->server.timeout);

	if (ctl->smtp_socket != -1)
	    close(ctl->smtp_socket);
	if (sock != -1)
	    close(sock);
	if (sinkfp)
	    pclose(sinkfp);
	ok = PS_ERROR;
    }
    else
    {
	char buf [POPBUFSIZE+1], *realhost;
	int *msgsizes, len, num, count, new, bytes, deletions = 0;
#if INET6
	int fetches, dispatches;
#else /* INET6 */
	int port, fetches, dispatches;
#endif /* INET6 */
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
#if !INET6
	port = ctl->server.port ? ctl->server.port : protocol->port;
#endif /* !INET6 */
	realhost = ctl->server.via ? ctl->server.via : ctl->server.pollname;
#if INET6
	if ((sock = SockOpen(realhost, 
			     ctl->server.service ? ctl->server.service : protocol->service,
			     ctl->server.netsec)) == -1)
#else /* INET6 */
	if ((sock = SockOpen(realhost, port, NULL)) == -1)
#endif /* INET6 */
	{
#if !INET6
#ifndef EHOSTUNREACH
#define EHOSTUNREACH (-1)
#endif
	    if (outlevel == O_VERBOSE || errno != EHOSTUNREACH)
	    {
		error_build("fetchmail: %s connection to %s failed: ", 
			     protocol->name, ctl->server.pollname);
#ifdef HAVE_RES_SEARCH
		if (h_errno == HOST_NOT_FOUND)
		    error_complete(0, 0, "host is unknown");
		else if (h_errno == NO_ADDRESS)
		    error_complete(0, 0, "name is valid but has no IP address");
		else if (h_errno == NO_RECOVERY)
		    error_complete(0, 0, "unrecoverable name server error");
		else if (h_errno == TRY_AGAIN)
		    error_complete(0, 0, "temporary name server error");
		else if (h_errno)
		    error_complete(0, 0, "unknown DNS error %d", h_errno);
		else
#endif /* HAVE_RES_SEARCH */
		    error_complete(0, errno, "local error");
	    }
#endif /* INET6 */
	    ok = PS_SOCKET;
	    goto closeUp;
	}

#ifdef KERBEROS_V4
	if (ctl->server.preauthenticate == A_KERBEROS_V4)
	{
	    set_timeout(ctl->server.timeout);
	    ok = kerberos_auth(sock, ctl->server.truename);
	    set_timeout(0);
 	    if (ok != 0)
		goto cleanUp;
	}
#endif /* KERBEROS_V4 */

#ifdef KERBEROS_V5
	if (ctl->server.preauthenticate == A_KERBEROS_V5)
	{
	    set_timeout(ctl->server.timeout);
	    ok = kerberos5_auth(sock, ctl->server.truename);
	    set_timeout(0);
 	    if (ok != 0)
		goto cleanUp;
	}
#endif /* KERBEROS_V5 */

	/* accept greeting message from mail server */
	ok = (protocol->parse_response)(sock, buf);
	if (ok != 0)
	    goto cleanUp;

	/* try to get authorized to fetch mail */
	if (protocol->getauth)
	{
	    if (protocol->password_canonify)
		(protocol->password_canonify)(shroud, ctl->password);
	    else
		strcpy(shroud, ctl->password);

	    ok = (protocol->getauth)(sock, ctl, buf);
	    if (ok != 0)
	    {
		if (ok == PS_LOCKBUSY)
		    error(0, -1, "Lock-busy error on %s@%s",
			  ctl->remotename,
			  ctl->server.truename);
		else
		{
		    if (ok == PS_ERROR)
			ok = PS_AUTHFAIL;
		    error(0, -1, "Authorization failure on %s@%s", 
			  ctl->remotename,
			  ctl->server.truename);
		}
		goto cleanUp;
	    }
	}

	ctl->errcount = fetches = 0;

	/* now iterate over each folder selected */
	for (idp = ctl->mailboxes; idp; idp = idp->next)
	{
	    pass = 0;
	    do {
		dispatches = 0;
		++pass;

		if (outlevel >= O_VERBOSE)
		    if (idp->id)
			error(0, 0, "selecting or re-polling folder %s", idp->id);
		    else
			error(0, 0, "selecting or re-polling default folder");

		/* compute # of messages and number of new messages waiting */
		ok = (protocol->getrange)(sock, ctl, idp->id, &count, &new, &bytes);
		if (ok != 0)
		    goto cleanUp;

		/* 
		 * We need the size of each message before it's
		 * loaded in order to pass via the ESMTP SIZE
		 * option.  If the protocol has a getsizes method,
		 * we presume this means it doesn't get reliable
		 * sizes from message fetch responses.
		 */
		if (count > 0 && proto->getsizes)
		{
		    int	i;

		    msgsizes = (int *)alloca(sizeof(int) * count);
		    for (i = 0; i < count; i++)
			msgsizes[i] = -1;

		    ok = (proto->getsizes)(sock, count, msgsizes);
		    if (ok != 0)
			goto cleanUp;

		    if (bytes == -1)
		    {
			bytes = 0;
			for (i = 0; i < count; i++)
			    bytes += msgsizes[i];
		    }
		}

		/* show user how many messages we downloaded */
		if (idp->id)
		    (void) sprintf(buf, "%s at %s (folder %s)",
				   ctl->remotename, ctl->server.truename, idp->id);
		else
		    (void) sprintf(buf, "%s at %s",
				   ctl->remotename, ctl->server.truename);
		if (outlevel > O_SILENT)
		    if (count == -1)		/* only used for ETRN */
			error(0, 0, "Polling %s", ctl->server.truename);
		    else if (count != 0)
		    {
			if (new != -1 && (count - new) > 0)
			    error_build("%d message%s (%d seen) for %s",
				  count, count > 1 ? "s" : "", count-new, buf);
			else
			    error_build("%d message%s for %s", 
				  count, count > 1 ? "s" : "", buf);
			if (bytes == -1)
			    error_complete(0, 0, ".");
			else
			    error_complete(0, 0, " (%d bytes).", bytes);
		    }
		    else
		    {
			/* these are pointless in normal daemon mode */
			if (pass == 1 && (poll_interval == 0 || outlevel == O_VERBOSE))
			    error(0, 0, "No mail for %s", buf); 
		    }

		/* very important, this is where we leave the do loop */ 
		if (count == 0)
		    break;

		if (check_only)
		{
		    if (new == -1 || ctl->fetchall)
			new = count;
		    ok = ((new > 0) ? PS_SUCCESS : PS_NOMAIL);
		    goto cleanUp;
		}
		else if (count > 0)
		{    
		    flag	force_retrieval;

		    /*
		     * What forces this code is that in POP2 and
		     * IMAP2bis you can't fetch a message without
		     * having it marked `seen'.  In POP3 and IMAP4, on the
		     * other hand, you can (peek_capable is set by 
		     * each driver module to convey this; it's not a
		     * method constant because of the difference between
		     * IMAP2bis and IMAP4).
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
		     * But in daemon mode this leads to the message
		     * being silently ignored forever.  This is not
		     * acceptable.
		     *
		     * We compensate for this by checking the error
		     * count from the previous pass and forcing all
		     * messages to be considered new if it's nonzero.
		     */
		    force_retrieval = !peek_capable && (ctl->errcount > 0);

		    /* read, forward, and delete messages */
		    for (num = 1; num <= count; num++)
		    {
			flag toolarge = NUM_NONZERO(ctl->limit)
			    && msgsizes && (msgsizes[num-1] > ctl->limit);
			flag fetch_it = !toolarge 
			    && (ctl->fetchall || force_retrieval || !(protocol->is_old && (protocol->is_old)(sock,ctl,num)));
			flag suppress_delete = FALSE;
			flag suppress_forward = FALSE;
			flag suppress_readbody = FALSE;
			flag retained = FALSE;

			/*
			 * This check copes with Post Office/NT's
			 * annoying habit of randomly prepending bogus
			 * LIST items of length -1.  Patrick Audley
			 * <paudley@pobox.com> tells us: LIST shows a
			 * size of -1, RETR and TOP return "-ERR
			 * System error - couldn't open message", and
			 * DELE succeeds but doesn't actually delete
			 * the message.
			 */
			if (msgsizes && msgsizes[num-1] == -1)
			{
			    if (outlevel >= O_VERBOSE)
				error(0, 0, 
				      "Skipping message %d, length -1",
				      num - 1);
			    continue;
			}

			/* we may want to reject this message if it's old */
			if (!fetch_it)
			{
			    if (outlevel > O_SILENT)
			    {
				error_build("skipping message %d", num);
				if (toolarge)
				    error_build(" (oversized, %d bytes)",
						msgsizes[num-1]);
			    }
			}
			else
			{
			    flag wholesize = !protocol->fetch_body;

			    /* request a message */
			    ok = (protocol->fetch_headers)(sock,ctl,num, &len);
			    if (ok != 0)
				goto cleanUp;

			    /* -1 means we didn't see a size in the response */
			    if (len == -1 && msgsizes)
			    {
				len = msgsizes[num - 1];
				wholesize = TRUE;
			    }

			    if (outlevel > O_SILENT)
			    {
				error_build("reading message %d of %d",
					    num,count);

				if (len > 0)
				    error_build(" (%d %sbytes)",
					len, wholesize ? "" : "header ");
				if (outlevel == O_VERBOSE)
				    error_complete(0, 0, "");
				else
				    error_build(" ");
			    }

			    /* later we'll test for this before closing */
			    sinkfp = (FILE *)NULL;

			    /* 
			     * Read the message headers and ship them to the
			     * output sink.  
			     */
			    ok = readheaders(sock, len, msgsizes[num-1],
					     ctl, num);
			    if (ok == PS_RETAINED)
				suppress_forward = retained = TRUE;
			    else if (ok == PS_TRANSIENT)
				suppress_delete = suppress_forward = TRUE;
			    else if (ok == PS_REFUSED)
				suppress_forward = TRUE;
			    else if (ok == PS_TRUNCATED)
				suppress_readbody = TRUE;
			    else if (ok)
				goto cleanUp;

			    /* 
			     * If we're using IMAP4 or something else that
			     * can fetch headers separately from bodies,
			     * it's time to request the body now.  This
			     * fetch may be skipped if we got an anti-spam
			     * or other PS_REFUSED error response during
			     * read_headers.
			     */
			    if (protocol->fetch_body && !suppress_readbody) 
			    {
				if (outlevel == O_VERBOSE)
				    fputc('\n', stderr);

				if ((ok = (protocol->trail)(sock, ctl, num)))
				    goto cleanUp;
				len = 0;
				if (!suppress_forward)
				{
				    if ((ok=(protocol->fetch_body)(sock,ctl,num,&len)))
					goto cleanUp;
				    if (outlevel > O_SILENT && !wholesize)
					error_build(" (%d body bytes) ", len);
				}
			    }

			    /* process the body now */
			    if (len > 0)
			    {
			        if (suppress_readbody)
				{
				  /* When readheaders returns PS_TRUNCATED,
				     the body (which has no content
				     has already been read by readheaders,
				     so we say readbody returned PS_SUCCESS */
				  ok = PS_SUCCESS;
				}
				else
				{
				  ok = readbody(sock,
					        ctl,
					        !suppress_forward,
					        len);
				}
			        if (ok == PS_TRANSIENT)
				    suppress_delete = suppress_forward = TRUE;
				else if (ok)
				    goto cleanUp;

				/* tell server we got it OK and resynchronize */
				if (protocol->trail)
				{
				    if (outlevel == O_VERBOSE)
					fputc('\n', stderr);

				    ok = (protocol->trail)(sock, ctl, num);
				    if (ok != 0)
					goto cleanUp;
				}
			    }

			    /* count # messages forwarded on this pass */
			    if (!suppress_forward)
				dispatches++;

			    /*
			     * Check to see if the numbers matched?
			     *
			     * Yes, some servers foo this up horribly.
			     * All IMAP servers seem to get it right, and
			     * so does Eudora QPOP at least in 2.xx
			     * versions.
			     *
			     * Microsoft Exchange gets it completely
			     * wrong, reporting compressed rather than
			     * actual sizes (so the actual length of
			     * message is longer than the reported size).
			     * Another fine example of Microsoft brain death!
			     *
			     * Some older POP servers, like the old UCB
			     * POP server and the pre-QPOP QUALCOMM
			     * versions, report a longer size in the LIST
			     * response than actually gets shipped up.
			     * It's unclear what is going on here, as the
			     * QUALCOMM server (at least) seems to be
			     * reporting the on-disk size correctly.
			     */
			    if (msgsizes && msglen != msgsizes[num-1])
			    {
				if (outlevel >= O_VERBOSE)
				    error(0, 0,
					  "message %d was not the expected length (%d != %d)",
					  num, msglen, msgsizes[num-1]);
			    }

			    /* end-of-message processing starts here */

			    if (ctl->mda)
			    {
				int rc;

				/* close the delivery pipe, we'll reopen before next message */
				if (sinkfp)
				    rc = pclose(sinkfp);
				else
				    rc = 0;
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
			 * At this point in flow of control, either
			 * we've bombed on a protocol error or had
			 * delivery refused by the SMTP server
			 * (unlikely -- I've never seen it) or we've
			 * seen `accepted for delivery' and the
			 * message is shipped.  It's safe to mark the
			 * message seen and delete it on the server
			 * now.
			 */

			/* tell the UID code we've seen this */
			if (ctl->newsaved)
			{
			    struct idlist	*sdp;

			    for (sdp = ctl->newsaved; sdp; sdp = sdp->next)
				if (sdp->val.status.num == num)
				    sdp->val.status.mark = UID_SEEN;
			}

			/* maybe we delete this message now? */
			if (retained)
			{
			    if (outlevel > O_SILENT) 
				error_complete(0, 0, " retained");
			}
			else if (protocol->delete
				 && !suppress_delete
				 && (fetch_it ? !ctl->keep : ctl->flush))
			{
			    deletions++;
			    if (outlevel > O_SILENT) 
				error_complete(0, 0, " flushed");
			    ok = (protocol->delete)(sock, ctl, num);
			    if (ok != 0)
				goto cleanUp;
#ifdef POP3_ENABLE
			    delete_str(&ctl->newsaved, num);
#endif /* POP3_ENABLE */
			}
			else if (outlevel > O_SILENT) 
			    error_complete(0, 0, " not flushed");

			/* perhaps this as many as we're ready to handle */
			if (NUM_NONZERO(ctl->fetchlimit) && ctl->fetchlimit <= fetches)
			    goto no_error;
		    }
		}
	    } while
		  /*
		   * Only re-poll if we had some actual forwards, allowed
		   * deletions and had no errors.
		   * Otherwise it is far too easy to get into infinite loops.
		   */
		  (dispatches && protocol->retry && !ctl->keep && !ctl->errcount);
	}

   no_error:
	ok = (protocol->logout_cmd)(sock, ctl);
	/*
	 * Hmmmm...arguably this would be incorrect if we had fetches but
	 * no dispatches (due to oversized messages, etc.)
	 */
	if (ok == 0)
	    ok = (fetches > 0) ? PS_SUCCESS : PS_NOMAIL;
	close(sock);
	goto closeUp;

    cleanUp:
	if (ok != 0 && ok != PS_SOCKET)
	    (protocol->logout_cmd)(sock, ctl);
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
    case PS_LOCKBUSY:
	msg = "lock busy on server";
	break;
    case PS_SMTP:
	msg = "SMTP transaction";
	break;
    case PS_DNS:
	msg = "DNS lookup";
	break;
    case PS_UNDEFINED:
	error(0, 0, "undefined");
	break;
    }
    if (ok==PS_SOCKET || ok==PS_AUTHFAIL || ok==PS_SYNTAX 
		|| ok==PS_IOERR || ok==PS_ERROR || ok==PS_PROTOCOL 
		|| ok==PS_LOCKBUSY || ok==PS_SMTP)
	error(0,-1, "%s error while fetching from %s", msg, ctl->server.pollname);

closeUp:
    /* execute post-initialization command, if any */
    if (ctl->postconnect && (ok = system(ctl->postconnect)))
    {
	char buf[80];

	sprintf(buf, "post-connection command failed with status %d", ok);
	error(0, 0, buf);
	if (ok == PS_SUCCESS)
	    ok = PS_SYNTAX;
    }

    signal(SIGALRM, sigsave);
    return(ok);
}

#if defined(HAVE_STDARG_H)
void gen_send(int sock, const char *fmt, ... )
/* assemble command in printf(3) style and send to the server */
#else
void gen_send(sock, fmt, va_alist)
/* assemble command in printf(3) style and send to the server */
int sock;		/* socket to which server is connected */
const char *fmt;	/* printf-style format */
va_dcl
#endif
{
    char buf [MSGBUFSIZE+1];
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
#ifdef HAVE_VSNPRINTF
    vsnprintf(buf + strlen(buf), sizeof(buf), fmt, ap);
#else
    vsprintf(buf + strlen(buf), fmt, ap);
#endif
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
    int oldphase = phase;	/* we don't have to be re-entrant */

    phase = SERVER_WAIT;
    set_timeout(mytimeout);
    if (SockRead(sock, buf, size) == -1)
    {
	set_timeout(0);
	phase = oldphase;
	return(PS_SOCKET);
    }
    else
    {
	set_timeout(0);
	if (buf[strlen(buf)-1] == '\n')
	    buf[strlen(buf)-1] = '\0';
	if (buf[strlen(buf)-1] == '\r')
	    buf[strlen(buf)-1] = '\0';
	if (outlevel == O_VERBOSE)
	    error(0, 0, "%s< %s", protocol->name, buf);
	phase = oldphase;
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
    char buf [MSGBUFSIZE+1];
    va_list ap;
    int oldphase = phase;	/* we don't have to be re-entrant */

    phase = SERVER_WAIT;

    if (protocol->tagged)
	(void) sprintf(buf, "%s ", GENSYM);
    else
	buf[0] = '\0';

#if defined(HAVE_STDARG_H)
    va_start(ap, fmt) ;
#else
    va_start(ap);
#endif
#ifdef HAVE_VSNPRINTF
    vsnprintf(buf + strlen(buf), sizeof(buf), fmt, ap);
#else
    vsprintf(buf + strlen(buf), fmt, ap);
#endif
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

    phase = oldphase;
    return(ok);
}

/* driver.c ends here */
