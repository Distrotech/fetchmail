/*
 * xalloca.c -- allocate space or die 
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#if defined(HAVE_ALLOCA_H)
#include <alloca.h>
#else
#ifdef _AIX
 #pragma alloca
#endif
#endif

#include "fetchmail.h"

#if defined(HAVE_VOIDPOINTER)
#define XALLOCATYPE void
#else
#define XALLOCATYPE char
#endif

XALLOCATYPE *
#ifdef __STDC__
xalloca (size_t n)
#else
xalloca (n)

int n;
#endif
{
    XALLOCATYPE *p;

    p = (XALLOCATYPE *) alloca(n);
    if (p == (XALLOCATYPE *) 0)
    {
	report(stderr, "alloca failed\n");
	exit(PS_UNDEFINED);
    }
    return(p);
}

/* xalloca.c ends here */
