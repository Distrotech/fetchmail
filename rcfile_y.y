%{
/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       rcfile_y.y
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
		Extensively hacked and fixed by esr.
  description:  configuration file parser

 ***********************************************************************/

#include <config.h>
#include <stdio.h>
extern char *rcfile;
extern int prc_lineno;
extern int prc_errflag;
extern char *yytext;

int yydebug;	/* in case we didn't generate with -- debug */
%}

%union {
  int proto;
  int flag;
  char *sval;
}

%token KW_SERVER KW_PROTOCOL KW_USERNAME KW_PASSWORD KW_RPOPID
%token KW_REMOTEFOLDER KW_LOCALFOLDER KW_SMTPHOST KW_MDA KW_EOL KW_DEFAULTS
%token <proto> PROTO_AUTO PROTO_POP2 PROTO_POP3 PROTO_IMAP PROTO_APOP PROTO_RPOP
%token <sval> PARAM_STRING
%token <flag> KW_KEEP KW_FLUSH KW_FETCHALL KW_REWRITE KW_PORT KW_EXPLICIT
%type <proto> proto;

/* these are actually used by the lexer */
%token TRUE	1
%token FALSE	0

%%

rcfile:		rcline
	|	rcfile rcline
  ;

rcline:		statement KW_EOL
  ;

statement:
	|	define_server			{prc_register(); prc_reset();}
  ;

define_server:	KW_SERVER PARAM_STRING server_options 	{prc_setserver($2);}
	|	KW_SERVER PARAM_STRING			{prc_setserver($2);}
	|	KW_DEFAULTS server_options	{prc_setserver("defaults");}
  ;

server_options:	serv_option_clause
	|	server_options serv_option_clause
  ;

serv_option_clause: 
		KW_PROTOCOL proto		{prc_setproto($2);}
	|	KW_USERNAME PARAM_STRING	{prc_remotename($2);}
	|	KW_PASSWORD PARAM_STRING	{prc_setpassword($2);}
	|	KW_RPOPID PARAM_STRING		{prc_setrpopid($2);}
	|	KW_REMOTEFOLDER PARAM_STRING	{prc_setremote($2);}
	|	KW_LOCALFOLDER PARAM_STRING	{prc_setlocal($2);}
	|	KW_SMTPHOST PARAM_STRING	{prc_setsmtphost($2);}
	|	KW_MDA PARAM_STRING		{prc_setmda($2);}
	|	KW_KEEP				{prc_setkeep($1);}
	|	KW_FLUSH			{prc_setflush($1);}
	|	KW_FETCHALL			{prc_setfetchall($1);}
	|	KW_REWRITE			{prc_setrewrite($1);}
	|	KW_EXPLICIT			{prc_setexplicit($1);}
	|	KW_PORT PARAM_STRING		{prc_setport($2);}
  ;

proto:		PROTO_POP2
	|	PROTO_POP3
	|	PROTO_IMAP
	|	PROTO_APOP
	|	PROTO_RPOP
  ;

%%


yyerror (s)
char *s;
{
  fprintf(stderr,"%s line %d: %s at %s\n", rcfile, prc_lineno, s, yytext);
  prc_errflag++;
}
