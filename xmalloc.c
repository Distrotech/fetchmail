/*
 * xmalloc.c -- allocate space or die 
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "fetchmail.h"

#if defined(HAVE_VOIDPOINTER)
#define XMALLOCTYPE void
#else
#define XMALLOCTYPE char
#endif

XMALLOCTYPE *
xmalloc (n)
int n;
{
  XMALLOCTYPE *p;

  p = (XMALLOCTYPE *) malloc(n);
  if (p == (XMALLOCTYPE *) 0) {
    fputs("fetchmail: malloc failed\n",stderr);
    exit(PS_UNDEFINED);
  }
  return(p);
}

char *xstrdup(s)
char *s;
{ 
  char *p;
  p = (char *) xmalloc(strlen(s)+1);
  strcpy(p,s);
  return p;
}

/* xmalloc.c ends here */
