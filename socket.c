/*
 * socket.c -- socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
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

    /*
     * Return of connect(2) doesn't seem to reliably return -1 on 
     * ENETUNREACH failure
     */
    errno = 0;
    connect(sock, (struct sockaddr *) &ad, sizeof(ad));
    if (errno != 0);
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
 * FIXME: This needs to be recoded to use stdio, if that's possible.
 *
 * If you think these functions are too slow and inefficient, you're
 * absolutely right.  I wish I could figure out what to do about it.
 * The ancestral popclient used static buffering here to cut down on the
 * number of read(2) calls, but we can't do that because we can have
 * two or more sockets open at a time.
 *
 * The right thing to do would be to use stdio for internal per-socket
 * buffering here (which is why Socket() returns a file pointer) but 
 * this causes mysterious lossage.  In case someone ever finds a way
 * around this, a note on Carl Harris's original implementation said:
 *
 * Size of buffer for internal buffering read function 
 * don't increase beyond the maximum atomic read/write size for
 * your sockets, or you'll take a potentially huge performance hit
 *
 * #define  INTERNAL_BUFSIZE	2048
 *
 */

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

/* socket.c ends here */
