/*
 * socket.c -- socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if defined(HAVE_STDARG_H)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "socket.h"

#ifndef  INADDR_NONE
#ifdef   INADDR_BROADCAST
#define  INADDR_NONE	INADDR_BROADCAST
#else
#define	 INADDR_NONE	-1
#endif
#endif

/*
 * Size of buffer for internal buffering read function 
 * don't increase beyond the maximum atomic read/write size for
 * your sockets, or you'll take a potentially huge performance hit
 */
#define  INTERNAL_BUFSIZE	2048

FILE *sockopen(char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
    FILE *fp;

    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;

    inaddr = inet_addr(host);
    if (inaddr != INADDR_NONE)
        memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
    else
    {
        hp = gethostbyname(host);
        if (hp == NULL)
            return (FILE *)NULL;
        memcpy(&ad.sin_addr, hp->h_addr, hp->h_length);
    }
    ad.sin_port = htons(clientPort);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return (FILE *)NULL;
    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0)
    {
	close(sock);
        return (FILE *)NULL;
    }
    fp = fdopen(sock, "r+");

    /* the point of all this mishigoss ... dynamic per-stream buffering */
    setvbuf(fp, NULL, _IOLBF, INTERNAL_BUFSIZE);

    return(fp);
}

#ifdef MAIN
/*
 * Use the chargen service to test buffering directly.
 */
main()
{
    FILE	*fp = sockopen("localhost", 19);
    char	buf[80];

    while (fgets(buf, sizeof(buf)-1, fp))
	fputs(buf, stdout);
}
#endif /* MAIN */

/* socket.c ends here */
