%{

/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       rcfile_l.l
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
		Extensively hacked by esr.
  description:  configuration lexer

 ***********************************************************************/

#include <config.h>
#include "fetchmail.h"
#include "rcfile_y.h"

int prc_lineno = 1;
%}

%%

defaults 	{ return KW_DEFAULTS; }
server 		{ return KW_SERVER; }
proto(col)? 	{ return KW_PROTOCOL; }
user(name)?	{ return KW_USERNAME; }
pass(word)?	{ return KW_PASSWORD; }
remote(folder)? { return KW_REMOTEFOLDER; }
smtp(host)?	{ return KW_SMTPHOST; }
keep		{ yylval.flag = FLAG_TRUE; return KW_KEEP; }
flush		{ yylval.flag = FLAG_TRUE; return KW_FLUSH; }
fetchall	{ yylval.flag = FLAG_TRUE; return KW_FETCHALL; }
rewrite		{ yylval.flag = FLAG_TRUE; return KW_REWRITE; }
skip		{ yylval.flag = FLAG_TRUE; return KW_SKIP; }
nokeep		{ yylval.flag = FLAG_FALSE; return KW_KEEP; }
noflush		{ yylval.flag = FLAG_FALSE; return KW_FLUSH; }
nofetchall	{ yylval.flag = FLAG_FALSE; return KW_FETCHALL; }
norewrite	{ yylval.flag = FLAG_FALSE; return KW_REWRITE; }
noskip		{ yylval.flag = FLAG_FALSE; return KW_SKIP; }
port		{ return KW_PORT; }

(auto)|(AUTO)	{ yylval.proto = P_AUTO;  return KW_PROTO; }
(pop2)|(POP2)	{ yylval.proto = P_POP2;  return KW_PROTO; }
(pop3)|(POP3)	{ yylval.proto = P_POP3;  return KW_PROTO; }
(imap)|(IMAP)	{ yylval.proto = P_IMAP;  return KW_PROTO; }
(apop)|(APOP)   { yylval.proto = P_APOP;  return KW_PROTO; }
(rpop)|(RPOP)   { yylval.proto = P_RPOP;  return KW_PROTO; }

(#.*)?\\?\n	{ prc_lineno++;	}   /* newline is ignored */

\"[^\"]*\"	{
			yytext[strlen(yytext)-1] = '\0';
			yylval.sval = (char *) strdup(yytext+1);
			return PARAM_STRING;
		}
[^ \t\r\n]+	{ yylval.sval = (char *) strdup(yytext); return PARAM_STRING; }

[ \t\r]+	;	/* whitespace */

