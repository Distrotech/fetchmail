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
  module:       xmalloc.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  malloc wrapper.

  $Log: xmalloc.c,v $
  Revision 1.1  1996/06/28 14:50:30  esr
  Initial revision

  Revision 1.1  1995/08/09 01:33:08  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

 ***********************************************************************/


#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include "popclient.h"

#if defined(HAVE_VOIDPOINTER)
#define XMALLOCTYPE void
#else
#define XMALLOCTYPE char
#endif

XMALLOCTYPE *
xmalloc (n)
size_t n;
{
  XMALLOCTYPE *p;

  p = (XMALLOCTYPE *) malloc(n);
  if (p == (XMALLOCTYPE *) 0) {
    fputs("malloc failed\n",stderr);
    exit(PS_UNDEFINED);
  }
  return(p);
}
