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

defaults 	{ return DEFAULTS; }
server 		{ return SERVER; }
proto(col)? 	{ return PROTOCOL; }
port		{ return PORT; }

user(name)?	{ return USERNAME; }
pass(word)?	{ return PASSWORD; }
remote(folder)? { return FOLDER; }
smtp(host)?	{ return SMTPHOST; }
mda		{ return MDA; }
is		{ return IS; }
here		{ return HERE; }
there		{ return THERE; }

keep		{ yylval.flag = FLAG_TRUE;  return KEEP; }
flush		{ yylval.flag = FLAG_TRUE;  return FLUSH; }
fetchall	{ yylval.flag = FLAG_TRUE;  return FETCHALL; }
rewrite		{ yylval.flag = FLAG_FALSE; return REWRITE; }
skip		{ yylval.flag = FLAG_TRUE;  return SKIP; }
nokeep		{ yylval.flag = FLAG_FALSE; return KEEP; }
noflush		{ yylval.flag = FLAG_FALSE; return FLUSH; }
nofetchall	{ yylval.flag = FLAG_FALSE; return FETCHALL; }
norewrite	{ yylval.flag = FLAG_TRUE;  return REWRITE; }
noskip		{ yylval.flag = FLAG_FALSE; return SKIP; }

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

(#.*)?\\?\n	{ prc_lineno++;	}   /* newline is ignored */

\"[^\"]*\"	{
			yytext[strlen(yytext)-1] = '\0';
			yylval.sval = (char *) strdup(yytext+1);
			return STRING;
		}
[^;:, \t\r\n]+	{ yylval.sval = (char *) strdup(yytext); return STRING; }

[ \t\r]+	;	/* whitespace */

