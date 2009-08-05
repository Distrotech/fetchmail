/* sdump.c -- library to allocate a printable version of a string */
/** \file sdump.c
 * \author Matthias Andree
 * \date 2009
 */

#include <ctype.h>  /* for isprint() */
#include <stdio.h>  /* for sprintf() */
#include <stdlib.h> /* for size_t */
#include "xmalloc.h" /* for xmalloc() */

#include "sdump.h"   /* for prototype */

/** sdump converts a byte string \a in of size \a len into a printable
 * string and returns a pointer to the memory region.
 * \returns a pointer to a xmalloc()ed string that the caller must
 * free() after use. This function causes program abort on failure. */
char *sdump(const char *in, size_t len)
{
    size_t outlen = 0, i;
    char *out, *oi;

    for (i = 0; i < len; i++) {
	outlen += isprint((unsigned char)in[i]) ? 1 : 4;
    }

    oi = out = (char *)xmalloc(outlen + 1);
    for (i = 0; i < len; i++) {
	if (isprint((unsigned char)in[i])) {
	    *(oi++) = in[i];
	} else {
	    oi += sprintf(oi, "\\x%02X", in[i]);
	}
    }
    *oi = '\0';
    return out;
}
