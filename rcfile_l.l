%{

/*
 * rcfile_l.l -- lexer for the run control file
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>
#include "fetchmail.h"
#include "rcfile_y.h"

int prc_lineno = 1;
%}

/* this doesn't work with Linux lex, see the INSTALL file */
%o 5000
%a 3000

%%

set		{ return SET; }
batchlimit	{ return BATCHLIMIT; }
fetchlimit	{ return FETCHLIMIT; }
logfile		{ return LOGFILE; }
defaults 	{ return DEFAULTS; }
server 		{ return POLL; }
poll		{ return POLL; }
skip		{ return SKIP; }
aka		{ return AKA; }
proto(col)? 	{ return PROTOCOL; }
port		{ return PORT; }
auth(enticate)?	{ return AUTHENTICATE; }
kerberos	{ return KERBEROS; }
timeout		{ return TIMEOUT;}
envelope	{ return ENVELOPE; }

user(name)?	{ return USERNAME; }
pass(word)?	{ return PASSWORD; }
remote(folder)? { return FOLDER; }
smtp(host)?	{ return SMTPHOST; }
mda		{ return MDA; }
is		{ return IS; }
here		{ return HERE; }
there		{ return THERE; }
to		{ return TO; }
=		{ return MAP; }
"*"		{ return WILDCARD; }

keep		{ yylval.flag = FLAG_TRUE;  return KEEP; }
flush		{ yylval.flag = FLAG_TRUE;  return FLUSH; }
fetchall	{ yylval.flag = FLAG_TRUE;  return FETCHALL; }
rewrite		{ yylval.flag = FLAG_FALSE; return REWRITE; }
nokeep		{ yylval.flag = FLAG_FALSE; return KEEP; }
noflush		{ yylval.flag = FLAG_FALSE; return FLUSH; }
nofetchall	{ yylval.flag = FLAG_FALSE; return FETCHALL; }
norewrite	{ yylval.flag = FLAG_TRUE;  return REWRITE; }
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
(imap)|(IMAP)	{ yylval.proto = P_IMAP;  return PROTO; }
(apop)|(APOP)   { yylval.proto = P_APOP;  return PROTO; }
(kpop)|(KPOP)	{ return KPOP; }


(#.*)?\\?\n	{ prc_lineno++;	}   /* newline is ignored */

[0-9]+		{ yylval.number = atoi(yytext); return NUMBER; }

\"[^\"]*\"	{
			char buf[POPBUFSIZE];

			yytext[strlen(yytext)-1] = '\0';
			escapes(yytext+1, buf);
			yylval.sval = (char *) xstrdup(buf);
			return STRING;
		}
[^;:, \t\r\n]+	{
			char buf[POPBUFSIZE];

			escapes(yytext, buf);
			yylval.sval = (char *) xstrdup(buf);
			return STRING;
		}

[ \t\r]+	;	/* whitespace */

