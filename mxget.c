/*
 * mxget.c -- fetch MX records for given DNS name
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>
#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "mx.h"

/*
 * This ought to be in the bind library.  It's adapted from sendmail.
 */

int getmxrecords(name, nmx, pmx)
/* get MX records for given host */
char *name;
int nmx;
struct mxentry *pmx;
{
    unsigned char answer[PACKETSZ], MXHostBuf[PACKETSZ], *eom, *cp, *bp;
    int n, ancount, qdcount, buflen, type, pref, ind;
    HEADER *hp;

    n = res_search(name,C_IN,T_MX,(unsigned char*)&answer, sizeof(answer));
    if (n == -1)
	return(-1);

    hp = (HEADER *)&answer;
    cp = answer + HFIXEDSZ;
    eom = answer + n;
    for (qdcount = ntohs(hp->qdcount); qdcount--; cp += n + QFIXEDSZ)
	if ((n = dn_skipname(cp, eom)) < 0)
	    return(-1);
    buflen = sizeof(MXHostBuf) - 1;
    bp = MXHostBuf;
    ind = 0;
    ancount = ntohs(hp->ancount);
    while (--ancount >= 0 && cp < eom)
    {
	if ((n = dn_expand(answer, eom, cp, bp, buflen)) < 0)
	    break;
	cp += n;
	GETSHORT(type, cp);
	cp += INT16SZ + INT32SZ;
	GETSHORT(n, cp);
	if (type != T_MX)
	{
	    cp += n;
	    continue;
	}
	GETSHORT(pref, cp);
	if ((n = dn_expand(answer, eom, cp, bp, buflen)) < 0)
	    break;
	cp += n;

	pmx[ind].name = bp;
	pmx[ind].pref = pref;
	if (++ind > nmx)
	    break;

	n = strlen(bp);
	bp += n;
	*bp++ = '\0';


	buflen -= n + 1;
    }

    return(ind);
}
#endif /* HAVE_GETHOSTBYNAME */

/* mxget.c ends here */
