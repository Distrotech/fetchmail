/*
 * rfc822.c -- code for slicing and dicing RFC822 mail headers
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include  <stdio.h>
#include  <ctype.h>
#include  <string.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif

#include  "fetchmail.h"

void reply_hack(buf, host)
/* hack message headers so replies will work properly */
char *buf;		/* header to be hacked */
const char *host;	/* server hostname */
{
    const char *from;
    int parendepth, state = 0, tokencount = 0;
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
	    {
		parendepth = 1;
		state = 4;    
	    }
	    else if (*from == '<' || isalnum(*from))
		state = 5;
	    else if (isspace(*from))
		state = 2;
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
	    if (*from == '(')
		++parendepth;
	    else if (*from == ')')
		--parendepth;
	    if (parendepth == 0)
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
		tokencount = 0;
		state = 1;
	    }

	    /* a single local name alone on the line */
	    else if (*from == '\n' && tokencount == 1)
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

char *nxtaddr(hdr)
/* parse addresses in succession out of a specified RFC822 header */
const char *hdr;	/* header to be parsed, NUL to continue previous hdr */
{
    static char *tp, address[POPBUFSIZE+1];
    static const char *hp;
    static int	state;
    int parendepth;

    /*
     * Note 1: RFC822 escaping with \ is *not* handled.  Note 2: it is
     * important that this routine not stop on \r, since we use \r as
     * a marker for RFC822 continuations elsewhere.
     */
#define START_HDR	0	/* before header colon */
#define BARE_ADDRESS	1	/* collecting address without delimiters */
#define INSIDE_DQUOTE	2	/* inside double quotes */
#define INSIDE_PARENS	3	/* inside parentheses */
#define INSIDE_BRACKETS	4	/* inside bracketed address */
#define STR_INSIDE_BR	5	/* copying string within bracketed address */
#define ENDIT_ALL	6	/* after last address */

    if (hdr)
    {
	hp = hdr;
	state = START_HDR;
    }

    for (; *hp; hp++)
    {
	switch (state)
	{
	case START_HDR:   /* before header colon */
	    if (*hp == '\n')
	    {
		state = ENDIT_ALL;
		return(NULL);
	    }
	    else if (*hp == ':')
	    {
		state = BARE_ADDRESS;
		tp = address;
	    }
	    break;

	case BARE_ADDRESS:   /* collecting address without delimiters */
	    if (*hp == '\n')	/* end of address list */
	    {
	        *tp++ = '\0';
		state = ENDIT_ALL;
		return(tp = address);
	    }
	    else if (*hp == ',')  /* end of address */
	    {
		if (tp > address)
		{
		    *tp++ = '\0';
		    ++hp;
		    return(tp = address);
		}
	    }
	    else if (*hp == '"') /* quoted string */
	    {
	        state = INSIDE_DQUOTE;
		*tp++ = *hp;
	    }
	    else if (*hp == '(') /* address comment -- ignore */
	    {
		parendepth = 1;
		state = INSIDE_PARENS;    
	    }
	    else if (*hp == '<') /* begin <address> */
	    {
		state = INSIDE_BRACKETS;
		tp = address;
	    }
	    else if (isspace(*hp)) /* ignore space */
	        state = BARE_ADDRESS;
	    else   /* just take it */
	    {
		state = BARE_ADDRESS;
		*tp++ = *hp;
	    }
	    break;

	case INSIDE_DQUOTE:   /* we're in a quoted string, copy verbatim */
	    if (*hp == '\n')
	    {
		state = ENDIT_ALL;
		return(NULL);
	    }
	    if (*hp != '"')
	        *tp++ = *hp;
	    else
	    {
	        *tp++ = *hp;
		state = BARE_ADDRESS;
	    }
	    break;

	case INSIDE_PARENS:   /* we're in a parenthesized comment, ignore */
	    if (*hp == '\n')
		return(NULL);
	    else if (*hp == '(')
		++parendepth;
	    else if (*hp == ')')
		--parendepth;
	    if (parendepth == 0)
		state = BARE_ADDRESS;
	    break;

	case INSIDE_BRACKETS:   /* possible <>-enclosed address */
	    if (*hp == '>') /* end of address */
	    {
		*tp++ = '\0';
		state = BARE_ADDRESS;
		++hp;
		return(tp = address);
	    }
	    else if (*hp == '<')  /* nested <> */
	        tp = address;
	    else if (*hp == '"') /* quoted address */
	    {
	        *tp++ = *hp;
		state = STR_INSIDE_BR;
	    }
	    else  /* just copy address */
		*tp++ = *hp;
	    break;

	case STR_INSIDE_BR:   /* we're in a quoted address, copy verbatim */
	    if (*hp == '\n')  /* mismatched quotes */
	    {
		state = ENDIT_ALL;
		return(NULL);
	    }
	    if (*hp != '"')  /* just copy it if it isn't a quote */
	        *tp++ = *hp;
	    else if (*hp == '"')  /* end of quoted string */
	    {
	        *tp++ = *hp;
		state = INSIDE_BRACKETS;
	    }
	    break;

	case ENDIT_ALL:	/* after last address */
	    return(NULL);
	    break;
	}
    }

    return(NULL);
}

#ifdef TESTMAIN
main(int argc, char *argv[])
{
    char	buf[POPBUFSIZE], *cp;

    while (fgets(buf, sizeof(buf)-1, stdin))
    {
	if (strncmp("From: ", buf, 6)
		    && strncmp("To: ", buf, 4)
		    && strncmp("Reply-", buf, 6)
		    && strncmp("Cc: ", buf, 4)
		    && strncmp("Bcc: ", buf, 5))
	    continue;
	else
	{
	    fputs(buf, stdout);
	    if ((cp = nxtaddr(buf)) != (char *)NULL)
		do {
		    printf("%s\n", cp);
		} while
		    ((cp = nxtaddr((char *)NULL)) != (char *)NULL);
	}

    }
}
#endif /* TESTMAIN */

/* rfc822.c end */
