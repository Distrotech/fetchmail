/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       xmalloc.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  malloc wrapper.

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
