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

FILE *Socket(char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
    
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
    return fdopen(sock, "r+");
}


#if defined(HAVE_STDARG_H)
int SockPrintf(FILE *sockfp, char* format, ...)
{
#else
int SockPrintf(sockfp,format,va_alist)
FILE *sockfp;
char *format;
va_dcl {
#endif

    va_list ap;
    char buf[8192];

#if defined(HAVE_STDARG_H)
    va_start(ap, format) ;
#else
    va_start(ap);
#endif
    vsprintf(buf, format, ap);
    va_end(ap);
    return SockWrite(buf, strlen(buf), sockfp);

}

/*
 * In case we ever optimize this further,
 * a note on Carl Harris's original implementation said:
 *
 * Size of buffer for internal buffering read function 
 * don't increase beyond the maximum atomic read/write size for
 * your sockets, or you'll take a potentially huge performance hit
 *
 * #define  INTERNAL_BUFSIZE	2048
 *
 */

int SockWrite(char *buf, int len, FILE *sockfp)
{
    int n;
    
    if ((n = fwrite(buf, 1, len, sockfp)) < 1)
	return -1;
    return n;
}

int SockGets(char *buf, int len, FILE *sockfp)
{
    int rdlen = 0;

    while (--len)
    {
        if ((*buf = fgetc(sockfp)) == EOF)
            return -1;
        else
	    rdlen++;
        if (*buf == '\n')
            break;
        if (*buf != '\r') /* remove all CRs */
            buf++;
    }
    *buf = 0;
    return rdlen;
}

/* socket.c ends here */
