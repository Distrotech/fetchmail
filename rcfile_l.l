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
keep		{ yylval.flag = TRUE; return KW_KEEP; }
flush		{ yylval.flag = TRUE; return KW_FLUSH; }
fetchall	{ yylval.flag = TRUE; return KW_FETCHALL; }
rewrite		{ yylval.flag = TRUE; return KW_REWRITE; }
skip		{ yylval.flag = TRUE; return KW_SKIP; }
nokeep		{ yylval.flag = FALSE; return KW_KEEP; }
noflush		{ yylval.flag = FALSE; return KW_FLUSH; }
nofetchall	{ yylval.flag = FALSE; return KW_FETCHALL; }
norewrite	{ yylval.flag = FALSE; return KW_REWRITE; }
noskip		{ yylval.flag = FALSE; return KW_SKIP; }
port		{ return KW_PORT; }

(auto)|(AUTO)	{ yylval.proto = P_AUTO;  return PROTO_AUTO; }
(pop2)|(POP2)	{ yylval.proto = P_POP2;  return PROTO_POP2; }
(pop3)|(POP3)	{ yylval.proto = P_POP3;  return PROTO_POP3; }
(imap)|(IMAP)	{ yylval.proto = P_IMAP;  return PROTO_IMAP; }
(apop)|(APOP)   { yylval.proto = P_APOP;  return PROTO_APOP; }
(rpop)|(RPOP)   { yylval.proto = P_RPOP;  return PROTO_RPOP; }

(#.*)?\\\n	{ prc_lineno++;	}   /* escaped newline is ignored */

(#.*)?\n	{ prc_lineno++; return KW_EOL; }

\"[^\"]*\"	{
			yytext[strlen(yytext)-1] = '\0';
			yylval.sval = (char *) strdup(yytext+1);
			return PARAM_STRING;
		}
[^ \t\r\n]+	{ yylval.sval = (char *) strdup(yytext); return PARAM_STRING; }

[ \t\r]+	;	/* whitespace */

