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
  module:       poprc_l.l
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  .poprc lexer

  $Log: rcfile_l.l,v $
  Revision 1.1  1996/06/24 18:16:08  esr
  Initial revision

  Revision 1.4  1995/08/10 00:32:43  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.3  1995/08/09 01:33:01  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.2  1995/08/08 01:01:34  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

 ***********************************************************************/

#include <config.h>
#include "poproto.h"
#include "poprc_y.h"

int prc_lineno = 0;
%}


%%

server 		{ return KW_SERVER; }
proto(col)? 	{ return KW_PROTOCOL; }
user(name)?	{ return KW_USERNAME; }
pass(word)?	{ return KW_PASSWORD; }
remote(folder)? { return KW_REMOTEFOLDER; }
local(folder)?	{ return KW_LOCALFOLDER; }

(pop2)|(POP2)	{ yylval.proto = P_POP2;  return PROTO_POP2; }
(pop3)|(POP3)	{ yylval.proto = P_POP3;  return PROTO_POP3; }
(imap)|(IMAP)	{ yylval.proto = P_IMAP;  return PROTO_IMAP; }
(apop)|(APOP)   { yylval.proto = P_APOP;  return PROTO_APOP; }
(rpop)|(RPOP)   { yylval.proto = P_RPOP;  return PROTO_RPOP; }

(#.*)?\\\n	{ prc_lineno++;	}   /* escaped newline is ignored */

(#.*)?\n	{ prc_lineno++; return KW_EOL; }

[^ \t\r\n#]+	{ yylval.sval = (char *) strdup(yytext); return PARAM_STRING; }

[ \t\r]+	;	/* whitespace */

