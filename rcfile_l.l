%{

/*
 * rcfile_l.l -- lexer for the run control file
 *
 * For license terms, see the file COPYING in this directory.
 */
#include <string.h>

#include "config.h"
#include "fetchmail.h"
#include "rcfile_y.h"

int prc_lineno = 1;
%}

/* this doesn't work with Linux lex, see the INSTALL file */
%o 6000
%a 4000
%p 3000

%%

set		{ return SET; }
logfile		{ return LOGFILE; }
daemon		{ return DAEMON; }
syslog		{ return SYSLOG; }
invisible	{ return INVISIBLE; }

defaults 	{ return DEFAULTS; }
server 		{ return POLL; }
poll		{ return POLL; }
skip		{ return SKIP; }
via		{ return VIA; }
aka		{ return AKA; }
local(domains)	{ return LOCALDOMAINS; }
proto(col)? 	{ return PROTOCOL; }
port		{ return PORT; }
interval	{ return INTERVAL; }
auth(enticate)?	{ return AUTHENTICATE; }
kerberos_v4	{ return KERBEROS4; }
kerberos	{ return KERBEROS4; }
timeout		{ return TIMEOUT;}
envelope	{ return ENVELOPE; }
qvirtual	{ return QVIRTUAL; }

user(name)?	{ return USERNAME; }
pass(word)?	{ return PASSWORD; }
folder(s)? 	{ return FOLDER; }
smtp(host)?	{ return SMTPHOST; }
mda		{ return MDA; }
pre(connect)?	{ return PRECONNECT; }
post(connect)?	{ return POSTCONNECT; }
interface	{ return INTERFACE; }
monitor		{ return MONITOR; }
batchlimit	{ return BATCHLIMIT; }
fetchlimit	{ return FETCHLIMIT; }
expunge		{ return EXPUNGE; }

is		{ return IS; }
here		{ return HERE; }
there		{ return THERE; }
to		{ return TO; }
=		{ return MAP; }
"*"		{ return WILDCARD; }

no/[kfrsdu \t].*	{ return NO;}

keep		{ return KEEP; }
flush		{ return FLUSH; }
fetchall	{ return FETCHALL; }
rewrite		{ return REWRITE; }
forcecr		{ return FORCECR; }
stripcr		{ return STRIPCR; }
pass8(bits)?	{ return PASS8BITS; }
dropstatus?	{ return DROPSTATUS; }
dns		{ return DNS; }
uidl		{ return UIDL; }

limit		{ return LIMIT; }

with		{/* EMPTY */}
and		{/* EMPTY */}
has		{/* EMPTY */}
wants		{/* EMPTY */}
options		{/* EMPTY */}
[;:,]		{/* EMPTY */}

(auto)|(AUTO)	{ yylval.proto = P_AUTO;  return PROTO; }
(pop2)|(POP2)	{ yylval.proto = P_POP2;  return PROTO; }
(pop3)|(POP3)	{ yylval.proto = P_POP3;  return PROTO; }
(imap-k4)|(IMAP-K4)   { yylval.proto = P_IMAP_K4;  return PROTO; }
(imap)|(IMAP)	{ yylval.proto = P_IMAP;  return PROTO; }
(apop)|(APOP)   { yylval.proto = P_APOP;  return PROTO; }
(etrn)|(ETRN)   { yylval.proto = P_ETRN;  return PROTO; }
(kpop)|(KPOP)	{ return KPOP; }

remote(folder)? {
		fprintf(stderr, 
			"fetchmail: `remote' keyword is gone, use `folder'\n");
		}


(#.*)?\\?\n	{ prc_lineno++;	}   /* newline is ignored */

[0-9]+		{ yylval.number = atoi(yytext); return NUMBER; }

\"[^\"]*\"	{
			char buf[POPBUFSIZE];

			yytext[strlen(yytext)-1] = '\0';
			escapes(yytext+1, buf);
			yylval.sval = (char *) xstrdup(buf);
			return STRING;
		}
[^=;:, \t\r\n]+	{
			char buf[POPBUFSIZE];

			escapes(yytext, buf);
			yylval.sval = (char *) xstrdup(buf);
			return STRING;
		}

[ \t\r]+	;	/* whitespace */

%%

void escapes(cp, tp)
/* process standard C-style escape sequences in a string */
const char	*cp;	/* source string with escapes */
char		*tp;	/* target buffer for digested string */
{
    while (*cp)
    {
	int	cval = 0;

	if (*cp == '\\' && strchr("0123456789xX", cp[1]))
	{
	    char *dp, *hex = "00112233445566778899aAbBcCdDeEfF";
	    int dcount = 0;

	    if (*++cp == 'x' || *cp == 'X')
		for (++cp; (dp = strchr(hex, *cp)) && (dcount++ < 2); cp++)
		    cval = (cval * 16) + (dp - hex) / 2;
	    else if (*cp == '0')
		while (strchr("01234567",*cp) != (char*)NULL && (dcount++ < 3))
		    cval = (cval * 8) + (*cp++ - '0');
	    else
		while ((strchr("0123456789",*cp)!=(char*)NULL)&&(dcount++ < 3))
		    cval = (cval * 10) + (*cp++ - '0');
	}
	else if (*cp == '\\')		/* C-style character escapes */
	{
	    switch (*++cp)
	    {
	    case '\\': cval = '\\'; break;
	    case 'n': cval = '\n'; break;
	    case 't': cval = '\t'; break;
	    case 'b': cval = '\b'; break;
	    case 'r': cval = '\r'; break;
	    default: cval = *cp;
	    }
	    cp++;
	}
	else
	    cval = *cp++;
	*tp++ = cval;
    }
    *tp = '\0';
}

