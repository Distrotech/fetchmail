/*
 * sink.c -- forwarding/delivery support for fetchmail
 *
 * The interface of this module (open_sink(), stuff_line(), close_sink(),
 * release_sink()) seals off the delivery logic from the protocol machine,
 * so the latter won't have to care whether it's shipping to an SMTP
 * listener daemon or an MDA pipe.
 *
 * Copyright 1998 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"
#include  <stdio.h>
#include  <errno.h>
#include  <string.h>
#include  <signal.h>
#ifdef HAVE_MEMORY_H
#include  <memory.h>
#endif /* HAVE_MEMORY_H */
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

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
	 * listeners that check for name match; we're going to lose
	 * on those anyway because we can never give them a name
	 * that matches the local machine fetchmail is running on.
	 * What it will affect is the listener's logging.
	 */
	struct idlist	*idp;
	const char *id_me = run.invisible ? ctl->server.truename : fetchmailhost;
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
	    char	*cp, *parsed_host;
#ifdef INET6 
	    char	*portnum = SMTP_PORT;
#else
	    int		portnum = SMTP_PORT;
#endif /* INET6 */

	    xalloca(parsed_host, char *, strlen(idp->id) + 1);

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
	    SockClose(ctl->smtp_socket);
	    ctl->smtp_socket = -1;

	    /* if opening for ESMTP failed, try SMTP */
	    if ((ctl->smtp_socket = SockOpen(parsed_host,portnum,NULL)) == -1)
		continue;

	    if (SMTP_ok(ctl->smtp_socket) == SM_OK && 
		    SMTP_helo(ctl->smtp_socket, id_me) == SM_OK)
		break;  /* success */

	    SockClose(ctl->smtp_socket);
	    ctl->smtp_socket = -1;
	}
	set_timeout(0);
	phase = oldphase;
    }

    /*
     * RFC 1123 requires that the domain name part of the
     * RCPT TO address be "canonicalized", that is a FQDN
     * or MX but not a CNAME.  Some listeners (like exim)
     * enforce this.  Now that we have the actual hostname,
     * compute what we should canonicalize with.
     */
    ctl->destaddr = ctl->smtpaddress ? ctl->smtpaddress : ( ctl->smtphost ? ctl->smtphost : "localhost");

    if (outlevel >= O_DEBUG && ctl->smtp_socket != -1)
	error(0, 0, "forwarding to %s", ctl->smtphost);

    return(ctl->smtp_socket);
}

/* these are shared by open_sink and stuffline */
static FILE *sinkfp;
static RETSIGTYPE (*sigchld)(int);

int stuffline(struct query *ctl, char *buf)
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
	if (ctl->server.base_protocol->delimited)	/* server has already byte-stuffed */
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

static void sanitize(char *s)
/* replace unsafe shellchars by an _ */
{
    const static char *ok_chars = " 1234567890!@%-_=+:,./abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *cp;

    for (cp = s; *(cp += strspn(cp, ok_chars)); /* NO INCREMENT */)
    	*cp = '_';
}

int open_sink(struct query *ctl, 
	      const char *return_path,
	      struct idlist *xmit_names,
	      long reallen,
	      int *good_addresses, int *bad_addresses)
/* set up sinkfp to be an input sink we can ship a message to */
{
    struct	idlist *idp;

    *bad_addresses = *good_addresses = 0;

    if (ctl->mda)		/* we have a declared MDA */
    {
	int	length = 0, fromlen = 0, nameslen = 0;
	char	*names = NULL, *before, *after, *from = NULL;

	ctl->destaddr = "localhost";

	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.status.mark == XMIT_ACCEPT)
		(*good_addresses)++;

	length = strlen(ctl->mda);
	before = xstrdup(ctl->mda);

	/* get user addresses for %T (or %s for backward compatibility) */
	if (strstr(before, "%s") || strstr(before, "%T"))
	{
	    /*
	     * We go through this in order to be able to handle very
	     * long lists of users and (re)implement %s.
	     */
	    nameslen = 0;
	    for (idp = xmit_names; idp; idp = idp->next)
		if ((idp->val.status.mark == XMIT_ACCEPT))
		    nameslen += (strlen(idp->id) + 1);	/* string + ' ' */
	    if ((*good_addresses == 0))
		nameslen = strlen(run.postmaster);

	    names = (char *)xmalloc(nameslen + 1);	/* account for '\0' */
	    if (*good_addresses == 0)
		strcpy(names, run.postmaster);
	    else
	    {
		names[0] = '\0';
		for (idp = xmit_names; idp; idp = idp->next)
		    if (idp->val.status.mark == XMIT_ACCEPT)
		    {
			strcat(names, idp->id);
			strcat(names, " ");
		    }
		names[--nameslen] = '\0';	/* chop trailing space */
	    }

	    /* sanitize names in order to contain only harmless shell chars */
	    sanitize(names);
	}

	/* get From address for %F */
	if (strstr(before, "%F"))
	{
	    from = xstrdup(return_path);

	    /* sanitize from in order to contain *only* harmless shell chars */
	    sanitize(from);

	    fromlen = strlen(from);
	}

	/* do we have to build an mda string? */
	if (names || from) 
	{		
	    char	*sp, *dp;

	    /* find length of resulting mda string */
	    sp = before;
	    while ((sp = strstr(sp, "%s"))) {
		length += nameslen - 2;	/* subtract %s */
		sp += 2;
	    }
	    sp = before;
	    while ((sp = strstr(sp, "%T"))) {
		length += nameslen - 2;	/* subtract %T */
		sp += 2;
	    }
	    sp = before;
	    while ((sp = strstr(sp, "%F"))) {
		length += fromlen - 2;	/* subtract %F */
		sp += 2;
	    }
		
	    after = xmalloc(length + 1);

	    /* copy mda source string to after, while expanding %[sTF] */
	    for (dp = after, sp = before; (*dp = *sp); dp++, sp++) {
		if (sp[0] != '%')	continue;

		/* need to expand? BTW, no here overflow, because in
		** the worst case (end of string) sp[1] == '\0' */
		if (sp[1] == 's' || sp[1] == 'T') {
		    strcpy(dp, names);
		    dp += nameslen;
		    sp++;	/* position sp over [sT] */
		    dp--;	/* adjust dp */
		} else if (sp[1] == 'F') {
		    strcpy(dp, from);
		    dp += fromlen;
		    sp++;	/* position sp over F */
		    dp--;	/* adjust dp */
		}
	    }

	    if (names) {
		free(names);
		names = NULL;
	    }
	    if (from) {
		free(from);
		from = NULL;
	    }

	    free(before);

	    before = after;
	}


	if (outlevel >= O_DEBUG)
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
	before = NULL;

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
	const char	*ap;
	char	options[MSGBUFSIZE], addr[128];

	/* build a connection to the SMTP listener */
	if ((smtp_open(ctl) == -1))
	{
	    error(0, errno, "SMTP connect to %s failed",
		  ctl->smtphost ? ctl->smtphost : "localhost");
	    return(PS_SMTP);
	}

	/*
	 * Compute ESMTP options.
	 */
	options[0] = '\0';
	if (ctl->server.esmtp_options & ESMTP_8BITMIME) {
             if (ctl->pass8bits || (ctl->mimemsg & MSG_IS_8BIT))
		strcpy(options, " BODY=8BITMIME");
             else if (ctl->mimemsg & MSG_IS_7BIT)
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

	    if (str_find(&ctl->antispam, smtperr))
	    {
		/*
		 * SMTP listener explicitly refuses to deliver mail
		 * coming from this address, probably due to an
		 * anti-spam domain exclusion.  Respect this.  Don't
		 * try to ship the message, and don't prevent it from
		 * being deleted.  Typical values:
		 *
		 * 501 = exim's old antispam response
		 * 550 = exim's new antispam response (temporary)
		 * 553 = sendmail 8.8.7's generic REJECT 
		 * 571 = sendmail's "unsolicited email refused"
		 *
		 * We don't send bouncemail on antispam failures because
		 * we don't want the scumbags to know the address is even
		 * valid.
		 */
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
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
		return(PS_REFUSED);

	    default:	/* retry with postmaster's address */
		if (SMTP_from(ctl->smtp_socket,run.postmaster,options)!=SM_OK)
		{
		    error(0, -1, "SMTP error: %s", smtp_response);
		    return(PS_SMTP);	/* should never happen */
		}
	    }
	}

	/*
	 * Now list the recipient addressees
	 */
	for (idp = xmit_names; idp; idp = idp->next)
	    if (idp->val.status.mark == XMIT_ACCEPT)
	    {
		if (strchr(idp->id, '@'))
		    strcpy(addr, idp->id);
		else
#ifdef HAVE_SNPRINTF
		    snprintf(addr, sizeof(addr)-1, "%s@%s", idp->id, ctl->destaddr);
#else
		    sprintf(addr, "%s@%s", idp->id, ctl->destaddr);
#endif /* HAVE_SNPRINTF */

		if (SMTP_rcpt(ctl->smtp_socket, addr) == SM_OK)
		    (*good_addresses)++;
		else
		{
		    (*bad_addresses)++;
		    idp->val.status.mark = XMIT_ANTISPAM;
		    error(0, 0, 
			  "SMTP listener doesn't like recipient address `%s'",
			  addr);
		}
	    }
	if (!(*good_addresses))
	{
#ifdef HAVE_SNPRINTF
	    snprintf(addr, sizeof(addr)-1, "%s@%s", run.postmaster, ctl->destaddr);
#else
	    sprintf(addr, "%s@%s", run.postmaster, ctl->destaddr);
#endif /* HAVE_SNPRINTF */

	    if (SMTP_rcpt(ctl->smtp_socket, addr) != SM_OK)
	    {
		error(0, 0, "can't even send to %s!", run.postmaster);
		SMTP_rset(ctl->smtp_socket);	/* required by RFC1870 */
		return(PS_SMTP);
	    }
	}

	/* tell it we're ready to send data */
	SMTP_data(ctl->smtp_socket);
    }

    return(PS_SUCCESS);
}

void release_sink(struct query *ctl)
/* release the per-message output sink, whether it's a pipe or SMTP socket */
{
    if (ctl->mda)
    {
	if (sinkfp)
	{
	    pclose(sinkfp);
	    sinkfp = (FILE *)NULL;
	}
	signal(SIGCHLD, sigchld);
    }
}

int close_sink(struct query *ctl, flag forward)
/* perform end-of-message actions on the current output sink */
{
    if (ctl->mda)
    {
	int rc;

	/* close the delivery pipe, we'll reopen before next message */
	if (sinkfp)
	{
	    rc = pclose(sinkfp);
	    sinkfp = (FILE *)NULL;
	}
	else
	    rc = 0;
	signal(SIGCHLD, sigchld);
	if (rc)
	{
	    error(0, -1, "MDA exited abnormally or returned nonzero status");
	    return(FALSE);
	}
    }
    else if (forward)
    {
				/* write message terminator */
	if (SMTP_eom(ctl->smtp_socket) != SM_OK)
	{
	    error(0, -1, "SMTP listener refused delivery");
	    return(FALSE);
	}
    }

    return(TRUE);
}

/* sink.c ends here */
