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

%token DEFAULTS SERVER PROTOCOL 
%token USERNAME PASSWORD FOLDER SMTPHOST MDA IS HERE THERE
%token <proto> PROTO
%token <sval>  STRING
%token <flag>  KEEP FLUSH FETCHALL REWRITE PORT SKIP

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

define_server	: SERVER STRING		{prc_setserver($2);}
		| SKIP SERVER STRING	{prc_setserver($3);
						prc_setskip($1==FLAG_TRUE);}
		| DEFAULTS		{prc_setserver("defaults");}
  		;

serverspecs	: /* EMPTY */
		| serverspecs serv_option
		;

serv_option	: PROTOCOL PROTO	{prc_setproto($2);}
		| PORT STRING		{prc_setport($2);}
		| SKIP			{prc_setskip($1==FLAG_TRUE);}
		;

/* the first and only the first user spec may omit the USERNAME part */
userspecs	: user1opts		{prc_register(); prc_reset();}
		| user1opts explicits	{prc_register(); prc_reset();}
		| explicits
		;

explicits	: explicitdef		{prc_register(); prc_reset();}
		| explicits explicitdef	{prc_register(); prc_reset();}
		;

explicitdef	: userdef user0opts
		;

userdef		: USERNAME STRING	{prc_setremote($2);}
		| USERNAME STRING HERE	{prc_setlocal($2);}
		| USERNAME STRING THERE	{prc_setremote($2);}
		;

user0opts	: /* EMPTY */
		| user0opts user_option
		;

user1opts	: user_option
		| user1opts user_option
		;

user_option	: IS STRING		{prc_setlocal($2);}
		| IS STRING HERE	{prc_setlocal($2);}
		| IS STRING THERE	{prc_setremote($2);}
		| PASSWORD STRING	{prc_setpassword($2);}
		| FOLDER  STRING 	{prc_setfolder($2);}
		| SMTPHOST STRING	{prc_setsmtphost($2);}
		| MDA STRING		{prc_setmda($2);}

		| KEEP			{prc_setkeep($1==FLAG_TRUE);}
		| FLUSH			{prc_setflush($1==FLAG_TRUE);}
		| FETCHALL		{prc_setfetchall($1==FLAG_TRUE);}
		| REWRITE		{prc_setrewrite($1==FLAG_TRUE);}
		;
%%

yyerror (s)
char *s;
{
  fprintf(stderr,"%s line %d: %s at %s\n", rcfile, prc_lineno, s, yytext);
  prc_errflag++;
}
