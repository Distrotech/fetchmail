/*
 * env.c -- small service routines
 *
 * Copyright 1998 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include <stdio.h>
#include <ctype.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <pwd.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#endif /* HAVE_GETHOSTBYNAME */
#include  <sys/types.h>
#include  <time.h>
#include "fetchmail.h"

#include "i18n.h"

extern char *getenv();	/* needed on sysV68 R3V7.1. */

extern char *program_name;

void envquery(int argc, char **argv)
/* set up basic stuff from the environment (including the rc file name) */
{
    struct passwd *pw;

    if ((program_name = strrchr(argv[0], '/')) != NULL)
	++program_name;
    else
	program_name = argv[0];

    if ((user = getenv("USER")) == (char *)NULL)
        user = getenv("LOGNAME");

    if ((user == (char *)NULL) || (home = getenv("HOME")) == (char *)NULL)
    {
	if ((pw = getpwuid(getuid())) != NULL)
	{
	    user = pw->pw_name;
	    home = pw->pw_dir;
	}
	else
	{
	    fprintf(stderr,
		    _("%s: can't find your name and home directory!\n"),
		    program_name);
	    exit(PS_UNDEFINED);
	}
    }

#define RCFILE_NAME	".fetchmailrc"
    rcfile = (char *) xmalloc(strlen(home)+strlen(RCFILE_NAME)+2);
    /* avoid //.fetchmailrc */
    if (strcmp(home, "/") != 0) {
    	strcpy(rcfile, home);
    } else {
    	*rcfile = '\0';
    }
    strcat(rcfile, "/");
    strcat(rcfile, RCFILE_NAME);
}

char *host_fqdn(void)
/* get the FQDN of the machine we're running */
{
    char	tmpbuf[HOSTLEN+1];

    if (gethostname(tmpbuf, sizeof(tmpbuf)))
    {
	fprintf(stderr, _("%s: can't determine your host!"),
		program_name);
	exit(PS_DNS);
    }
#ifdef HAVE_GETHOSTBYNAME
    /* if we got a . in the hostname assume it is a FQDN */
    if (strchr(tmpbuf, '.') == NULL)
    {
	struct hostent *hp;

	/* if we got a basename (as we do in Linux) make a FQDN of it */
	hp = gethostbyname(tmpbuf);
	if (hp == (struct hostent *) NULL)
	{
	    /* exit with error message */
	    fprintf(stderr,
		    _("gethostbyname failed for %s\n"), tmpbuf);
	    exit(PS_DNS);
	}
	return(xstrdup(hp->h_name));
    }
    else
#endif /* HAVE_GETHOSTBYNAME */
	return(xstrdup(tmpbuf));
}

char *rfc822timestamp(void)
/* return a timestamp in RFC822 form */
{
    time_t	now;
    static char buf[40];

    time(&now);
#ifdef HAVE_STRFTIME
    /*
     * Conform to RFC822. UTC rather than local time because of the
     * mess that %Z generates obsolete 822 syntax but %z is not
     * guaranteed portable. We generate a 4-digit year here, avoiding
     * Y2K hassles.  Max length of this timestamp in an English locale
     * should be 29 chars.  The only things that should vary by locale
     * are the day and month abbreviations.
     */
    strftime(buf, sizeof(buf)-1, 
	     "%a, %d %b %Y %H:%M:%S +0000 (UTC)",
	     gmtime(&now));
#else
    /*
     * This is really just a portability fallback, as the
     * date format ctime(3) emits is not RFC822
     * conformant.
     */
    strcpy(buf, ctime(&now));
    buf[strlen(buf)-1] = '\0';	/* remove trailing \n */
#endif /* HAVE_STRFTIME */

    return(buf);
}

const char *showproto(int proto)
/* protocol index to protocol name mapping */
{
    switch (proto)
    {
    case P_AUTO: return("auto"); break;
#ifdef POP2_ENABLE
    case P_POP2: return("POP2"); break;
#endif /* POP2_ENABLE */
    case P_POP3: return("POP3"); break;
    case P_IMAP: return("IMAP"); break;
    case P_IMAP_K4: return("IMAP-K4"); break;
#ifdef GSSAPI
    case P_IMAP_GSS: return("IMAP-GSS"); break;
#endif /* GSSAPI */
    case P_APOP: return("APOP"); break;
    case P_RPOP: return("RPOP"); break;
    case P_ETRN: return("ETRN"); break;
    default: return("unknown?!?"); break;
    }
}

char *visbuf(const char *buf)
/* visibilize a given string */
{
    static char vbuf[BUFSIZ];
    char *tp = vbuf;

    while (*buf)
    {
	if (*buf == '"')
	{
	    *tp++ = '\\'; *tp++ = '"';
	    buf++;
	}
	else if (isprint(*buf) || *buf == ' ')
	    *tp++ = *buf++;
	else if (*buf == '\n')
	{
	    *tp++ = '\\'; *tp++ = 'n';
	    buf++;
	}
	else if (*buf == '\r')
	{
	    *tp++ = '\\'; *tp++ = 'r';
	    buf++;
	}
	else if (*buf == '\b')
	{
	    *tp++ = '\\'; *tp++ = 'b';
	    buf++;
	}
	else if (*buf < ' ')
	{
	    *tp++ = '\\'; *tp++ = '^'; *tp++ = '@' + *buf;
	    buf++;
	}
	else
	{
	    (void) sprintf(tp, "\\0x%02x", *buf++);
	    tp += strlen(tp);
	}
    }
    *tp++ = '\0';
    return(vbuf);
}

/* env.c ends here */
