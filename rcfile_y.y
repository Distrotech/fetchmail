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

%token KW_SERVER KW_PROTOCOL KW_LOCALNAME KW_USERNAME KW_PASSWORD
%token KW_FOLDER KW_SMTPHOST KW_MDA KW_DEFAULTS
%token <proto> KW_PROTO
%token <sval>  PARAM_STRING
%token <flag>  KW_KEEP KW_FLUSH KW_FETCHALL KW_REWRITE KW_PORT KW_SKIP

/* these are actually used by the lexer */
%token FLAG_TRUE	2
%token FLAG_FALSE	1

%%

rcfile		: /* empty */
		| statement_list
		;

statement_list	: statement
		| statement_list statement
		;

statement	: define_server serverspecs userspecs      
		;

define_server	: KW_SERVER PARAM_STRING	{prc_setserver($2);}
		| KW_DEFAULTS			{prc_setserver("defaults");}
  		;

serverspecs	: /* EMPTY */
		| serverspecs serv_option
		;

serv_option	: KW_PROTOCOL KW_PROTO		{prc_setproto($2);}
		| KW_PORT PARAM_STRING		{prc_setport($2);}
		;

/* the first and only the first user spec may omit the KW_USERNAME part */
userspecs	: user1opts			{prc_register(); prc_reset();}
		| user1opts explicits		{prc_register(); prc_reset();}
		| explicits
		;

explicits	: userdef			{prc_register(); prc_reset();}
		| explicits userdef		{prc_register(); prc_reset();}
		;

userdef		: KW_USERNAME PARAM_STRING user0opts	{prc_setremote($2);}
		;

user0opts	: /* EMPTY */
		| user0opts user_option
		;

user1opts	: user_option
		| user1opts user_option
		;

user_option	: KW_LOCALNAME PARAM_STRING	{prc_setlocal($2);}
		| KW_PASSWORD PARAM_STRING	{prc_setpassword($2);}
		| KW_FOLDER  PARAM_STRING 	{prc_setfolder($2);}
		| KW_SMTPHOST PARAM_STRING	{prc_setsmtphost($2);}
		| KW_MDA PARAM_STRING		{prc_setmda($2);}

		| KW_KEEP		{prc_setkeep($1==FLAG_TRUE);}
		| KW_FLUSH		{prc_setflush($1==FLAG_TRUE);}
		| KW_FETCHALL		{prc_setfetchall($1==FLAG_TRUE);}
		| KW_REWRITE		{prc_setrewrite($1==FLAG_TRUE);}
		| KW_SKIP		{prc_setskip($1==FLAG_TRUE);}
		;
%%

yyerror (s)
char *s;
{
  fprintf(stderr,"%s line %d: %s at %s\n", rcfile, prc_lineno, s, yytext);
  prc_errflag++;
}
