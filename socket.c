/*
 * socket.c -- socket library functions
 *
 * These were designed and coded by Carl Harris <ceharris@mal.com>
 * and are essentially unchanged from the ancestral popclient.
 *
 * The file pointer arguments are currently misleading -- there
 * is only one shared internal buffer for all sockets.
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#if defined(STDC_HEADERS)
#include <string.h>
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
#include <errno.h>
#include "socket.h"

/* Size of buffer for internal buffering read function 
   don't increase beyond the maximum atomic read/write size for
   your sockets, or you'll take a potentially huge performance hit */

#define  INTERNAL_BUFSIZE	2048

FILE *Socket(host, clientPort)
char *host;
int clientPort;
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
        return (FILE *)NULL;
    return fdopen(sock, "r+");
}

int SockWrite(buf,len,sockfp)
char *buf;
int len;
FILE *sockfp;
{
    int n, wrlen = 0;
    
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

int SockGets(buf, len, sockfp)
char *buf;
int len;
FILE *sockfp;
{
    int rdlen = 0;

    while (--len)
    {
        if (read(fileno(sockfp), buf, 1) != 1)
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

/* socket.c ends here */
