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

/* #define USE_STDIO */

#ifdef USE_STDIO
/*
 * Size of buffer for internal buffering read function 
 * don't increase beyond the maximum atomic read/write size for
 * your sockets, or you'll take a potentially huge performance hit
 */
#define  INTERNAL_BUFSIZE	2048
#endif /* USE_STDIO */

FILE *SockOpen(char *host, int clientPort)
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
#ifdef USE_STDIO
    FILE *fp;
#endif /* USE_STDIO */

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

#ifndef USE_STDIO
    return fdopen(sock, "r+");
#else
    fp = fdopen(sock, "r+");

    setvbuf(fp, NULL, _IOLBF, INTERNAL_BUFSIZE);

    return(fp);
#endif /* USE_STDIO */
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
    return SockWrite(buf, 1, strlen(buf), sockfp);

}

#ifndef USE_STDIO
/*
 * FIXME: This needs to be recoded to use stdio, if that's possible.
 *
 * If you think these functions are too slow and inefficient, you're
 * absolutely right.  I wish I could figure out what to do about it.
 * The ancestral popclient used static buffering here to cut down on the
 * number of read(2) calls, but we can't do that because we can have
 * two or more sockets open at a time.
 *
 * The right thing to do would be to use stdio for internal per-socket
 * buffering here (which is why SockOpen() returns a file pointer) but 
 * this causes mysterious lossage.
 */

int SockWrite(char *buf, int size, int len, FILE *sockfp)
{
    int n, wrlen = 0;

    len *= size;
    while (len)
    {
        n = write(fileno(sockfp), buf, len);
        if (n <= 0)
            return -1;
        len -= n;
	wrlen += n;
	buf += n;
    }
    return wrlen;
}

char *SockGets(char *buf, int len, FILE *sockfp)
{
    int rdlen = 0;
    char *cp = buf;

    while (--len)
    {
        if (read(fileno(sockfp), cp, 1) != 1)
            return((char *)NULL);
        else
	    rdlen++;
        if (*cp++ == '\n')
            break;
    }
    *cp = 0;
    return buf;
}
#else

int SockWrite(char *buf, int size, int len, FILE *sockfp)
{
    return(fwrite(buf, size, len, sockfp));
}

char *SockGets(char *buf, int len, FILE *sockfp)
{
    return(fgets(buf, len, sockfp));
}

#endif

/* socket.c ends here */
