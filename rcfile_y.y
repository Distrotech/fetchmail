%{
/* Copyright 1993-95 by Carl Harris, Jr.
 * All rights reserved
 *
 * Distribute freely, except: don't remove my name from the source or
 * documentation (don't take credit for my work), mark your changes (don't
 * get me blamed for your possible bugs), don't alter or remove this
 * notice.  May be sold if buildable source is provided to buyer.  No
 * warrantee of any kind, express or implied, is included with this
 * software; use at your own risk, responsibility for damages (if any) to
 * anyone resulting from the use of this software rests entirely with the
 * user.
 *
 * Send bug reports, bug fixes, enhancements, requests, flames, etc., and
 * I'll try to keep a version up to date.  I can be reached as follows:
 * Carl Harris <ceharris@mal.com>
 */


/***********************************************************************
  module:       poprc_y.y
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  .poprc parser

  $Log: rcfile_y.y,v $
  Revision 1.1  1996/06/24 18:17:24  esr
  Initial revision

  Revision 1.4  1995/08/10 00:32:45  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.3  1995/08/09 01:33:02  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.2  1995/08/08 01:01:36  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

 ***********************************************************************/

#include <config.h>
#include <stdio.h>
extern char *prc_pathname;
extern int prc_lineno;
extern int prc_errflag;
extern char yytext[];
%}

%union {
  int proto;
  char *sval;
}

%token KW_SERVER KW_PROTOCOL KW_USERNAME KW_PASSWORD
%token KW_REMOTEFOLDER KW_LOCALFOLDER KW_EOL
%token <proto> PROTO_POP2 PROTO_POP3 PROTO_IMAP PROTO_APOP PROTO_RPOP
%token <sval> PARAM_STRING
%type <proto> proto;

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
  ;

server_options:	serv_option_clause
	|	server_options serv_option_clause
  ;

serv_option_clause: 
		KW_PROTOCOL proto		{prc_setproto($2);}
	|	KW_USERNAME PARAM_STRING	{prc_setusername($2);}
	|	KW_PASSWORD PARAM_STRING	{prc_setpassword($2);}
	|	KW_REMOTEFOLDER PARAM_STRING	{prc_setremote($2);}
	|	KW_LOCALFOLDER PARAM_STRING	{prc_setlocal($2);}
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
  fprintf(stderr,"%s line %d: %s at %s\n", prc_pathname, prc_lineno, s, yytext);
  prc_errflag++;
}
