/*
 * mxget.c -- fetch MX records for given DNS name
 *
 * Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
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

/* minimum possible size of MX record in packet */
#define MIN_MX_SIZE	8	/* corresp to "a.com 0" w/ terminating space */

struct mxentry *getmxrecords(name)
/* get MX records for given host */
const char *name;
{
    unsigned char answer[PACKETSZ], *eom, *cp, *bp;
    int n, ancount, qdcount, buflen, type, pref, ind;
    static struct mxentry pmx[(PACKETSZ - HFIXEDSZ) / MIN_MX_SIZE];
    static char MXHostBuf[PACKETSZ - HFIXEDSZ]; 
    HEADER *hp;

    n = res_search(name,C_IN,T_MX,(unsigned char*)&answer, sizeof(answer));
    if (n == -1)
	return((struct mxentry *)NULL);

    hp = (HEADER *)&answer;
    cp = answer + HFIXEDSZ;
    eom = answer + n;
    h_errno = 0;
    for (qdcount = ntohs(hp->qdcount); qdcount--; cp += n + QFIXEDSZ)
	if ((n = dn_skipname(cp, eom)) < 0)
	    return((struct mxentry *)NULL);
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
	++ind;

	n = strlen(bp);
	bp += n;
	*bp++ = '\0';

	buflen -= n + 1;
    }

    pmx[ind].name = (char *)NULL;
    pmx[ind].pref = -1;
    return(pmx);
}
#endif /* HAVE_GETHOSTBYNAME */

#ifdef TESTMAIN
main(int argc, char *argv[])
{
    int	count, i;
    struct mxentry *responses;

    responses = getmxrecords(argv[1]);
    if (responses == (struct mxentry *)NULL)
	puts("No MX records found");
    else
	do {
	    printf("%s %d\n", responses->name, responses->pref);
	} while
	    ((++responses)->name);
}
#endif /* TESTMAIN */

/* mxget.c ends here */
