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
    int parendepth, oldstate, state = 0, tokencount = 0, nlterm = 0;
    char mycopy[POPBUFSIZE+1];

    if (strncmp("From: ", buf, 6)
	&& strncmp("To: ", buf, 4)
	&& strncmp("Reply-", buf, 6)
	&& strncmp("Cc: ", buf, 4)
	&& strncmp("Bcc: ", buf, 5)) {
	return;
    }

    strcpy(mycopy, buf);
    if (mycopy[strlen(mycopy) - 1] == '\n')
    {
	mycopy[strlen(mycopy) - 1] = '\0';
	nlterm = TRUE;
    }
    if (mycopy[strlen(mycopy) - 1] != ',')
	strcat(mycopy, ",");

    for (from = mycopy; *from; from++)
    {
#ifdef FOO
	printf("state %d: %s", state, mycopy);
	printf("%*s^\n", from - mycopy + 10, " ");
#endif /* TESTMAIN */

#define INSERT_HOSTNAME	\
		strcpy(buf, "@"); \
		strcat(buf, host); \
		buf += strlen(buf); \
		state = 7;

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
		oldstate = 1;
		state = 4;    
	    }
	    else if (*from == '<')
		state = 5;
	    else if (isalnum(*from))
		state = 6;
	    else if (isspace(*from))
		state = 2;
	    break;

	case 2:	    /* found a token boundary -- reset without copying */
	    if (!isspace(*from))
	    {
		tokencount++;
		state = 1;
		--from;
		continue;
	    }
	    break;

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
		state = oldstate;
	    break;

	case 5:   /* we're in a <>-enclosed address */
	    if (*from == '@')
		state = 7;
	    else if (*from == '>')
	    {
		INSERT_HOSTNAME
	    }
	    break;

	case 6:   /* not string or comment, could be a bare address */
	    if (*from == '@')
		state = 7;

	    else if (*from == '<')
		state = 5;

	    else if (*from == '(')
	    {
		oldstate = 6;
		state = 4;
	    }

	    /* on proper termination with no @, insert hostname */
	    else if (*from == ',')
	    {
		INSERT_HOSTNAME
		tokencount = 0;
	    }

	    /* If the address token is not properly terminated, ignore it. */
	    else if (isspace(*from))
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
		    char	*bp = strchr(cp, '<');
		    char	*ep = strchr(cp, ',');

		    if (!bp || bp > ep)
		    {
			INSERT_HOSTNAME
		    }
		}
	    }

	    /* everything else, including alphanumerics, just passes through */
	    break;

	case 7:   /* we're done with this address, skip to end */
	    if (*from == ',')
	    {
		state = 1;
		tokencount == 0;
	    }
	    break;
	}

	/* all characters from the old buffer get copied to the new one */
	*buf++ = *from;
    }
#undef INSERT_HOSTNAME

    /* back up and nuke the appended comma sentinel */
    *--buf = '\0';

    if (nlterm)
	strcat(buf, "\n");
}

char *nxtaddr(hdr)
/* parse addresses in succession out of a specified RFC822 header */
const char *hdr;	/* header to be parsed, NUL to continue previous hdr */
{
    static char *tp, address[POPBUFSIZE+1];
    static const char *hp;
    static int	state, oldstate;
    int parendepth;

    /*
     * Note: it is important that this routine not stop on \r, since
     * we use \r as a marker for RFC822 continuations elsewhere.
     */
#define START_HDR	0	/* before header colon */
#define SKIP_JUNK	1	/* skip whitespace, \n, and junk */
#define BARE_ADDRESS	2	/* collecting address without delimiters */
#define INSIDE_DQUOTE	3	/* inside double quotes */
#define INSIDE_PARENS	4	/* inside parentheses */
#define INSIDE_BRACKETS	5	/* inside bracketed address */
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
		state = SKIP_JUNK;
		tp = address;
	    }
	    break;

	case SKIP_JUNK:		/* looking for address start */
	    if (*hp == '\n')		/* no more addresses */
	    {
		state = ENDIT_ALL;
		return(NULL);
	    }
	    else if (*hp == '\\')	/* handle RFC822 escaping */
	    {
	        *tp++ = *hp++;			/* take the escape */
	        *tp++ = *hp;			/* take following char */
	    }
	    else if (*hp == '"')	/* quoted string */
	    {
		oldstate = SKIP_JUNK;
	        state = INSIDE_DQUOTE;
		*tp++ = *hp;
	    }
	    else if (*hp == '(')	/* address comment -- ignore */
	    {
		parendepth = 1;
		state = INSIDE_PARENS;    
	    }
	    else if (*hp == '<')	/* begin <address> */
	    {
		state = INSIDE_BRACKETS;
		tp = address;
	    }
	    else if (!isspace(*hp))	/* ignore space */
	    {
		--hp;
	        state = BARE_ADDRESS;
	    }
	    break;

	case BARE_ADDRESS:   	/* collecting address without delimiters */
	    if (*hp == '\n')		/* end of bare address */
	    {
		if (tp > address)
		{
		    *tp++ = '\0';
		    state = ENDIT_ALL;
		    return(tp = address);
		}
	    }
	    else if (*hp == '\\')	/* handle RFC822 escaping */
	    {
	        *tp++ = *hp++;			/* take the escape */
	        *tp++ = *hp;			/* take following char */
	    }
	    else if (*hp == ',')  	/* end of address */
	    {
		if (tp > address)
		{
		    *tp++ = '\0';
		    state = SKIP_JUNK;
		    return(tp = address);
		}
	    }
	    else if (*hp == '<')  	/* beginning of real address */
	    {
		state = INSIDE_BRACKETS;
		tp = address;
	    }
	    else   		/* just take it */
		*tp++ = *hp;
	    break;

	case INSIDE_DQUOTE:	/* we're in a quoted string, copy verbatim */
	    if (*hp == '\n')		/* premature end of string */
	    {
		state = ENDIT_ALL;
		return(NULL);
	    }
	    else if (*hp == '\\')	/* handle RFC822 escaping */
	    {
	        *tp++ = *hp++;			/* take the escape */
	        *tp++ = *hp;			/* take following char */
	    }
	    else if (*hp != '"')
	        *tp++ = *hp;
	    else
	    {
	        *tp++ = *hp;
		state = oldstate;
	    }
	    break;

	case INSIDE_PARENS:	/* we're in a parenthesized comment, ignore */
	    if (*hp == '\n')		/* end of line, just bomb out */
		return(NULL);
	    else if (*hp == '\\')	/* handle RFC822 escaping */
	    {
	        *tp++ = *hp++;			/* take the escape */
	        *tp++ = *hp;			/* take following char */
	    }
	    else if (*hp == '(')
		++parendepth;
	    else if (*hp == ')')
		--parendepth;
	    if (parendepth == 0)
		state = SKIP_JUNK;
	    break;

	case INSIDE_BRACKETS:	/* possible <>-enclosed address */
	    if (*hp == '\\')		/* handle RFC822 escaping */
	    {
	        *tp++ = *hp++;			/* take the escape */
	        *tp++ = *hp;			/* take following char */
	    }
	    else if (*hp == '>')	/* end of address */
	    {
		*tp++ = '\0';
		state = SKIP_JUNK;
		++hp;
		return(tp = address);
	    }
	    else if (*hp == '<')	/* nested <> */
	        tp = address;
	    else if (*hp == '"')	/* quoted address */
	    {
	        *tp++ = *hp;
		oldstate = INSIDE_BRACKETS;
		state = INSIDE_DQUOTE;
	    }
	    else			/* just copy address */
		*tp++ = *hp;
	    break;

	case ENDIT_ALL:		/* after last address */
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
    int		reply =  (argc > 1 && !strcmp(argv[1], "-r"));

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
	    if (reply)
	    {
		reply_hack(buf, "HOSTNAME.NET");
		printf("Rewritten buffer: %s", buf);
	    }
	    else
		if ((cp = nxtaddr(buf)) != (char *)NULL)
		    do {
			printf("\t%s\n", cp);
		    } while
			((cp = nxtaddr((char *)NULL)) != (char *)NULL);
	}

    }
}
#endif /* TESTMAIN */

/* rfc822.c end */
