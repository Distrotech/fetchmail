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
  module:       md5ify.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  Simple interface to MD5 module.

  $Log: md5ify.c,v $
  Revision 1.1  1996/06/28 14:36:57  esr
  Initial revision

  Revision 1.1  1995/08/10 00:32:33  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

 ***********************************************************************/

#include <stdio.h>

#if defined(STDC_HEADERS)
#include <string.h>
#endif

#include "md5.h"

char *
MD5Digest (s)
char *s;
{
  int i;
  MD5_CTX context;
  unsigned char digest[16];
  static char ascii_digest [33];

  MD5Init(&context);
  MD5Update(&context, s, strlen(s));
  MD5Final(digest, &context);
  
  for (i = 0;  i < 16;  i++) 
    sprintf(ascii_digest+2*i, "%02x", digest[i]);
 
  return(ascii_digest);
}
