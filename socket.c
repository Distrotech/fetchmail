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

int SockPuts(buf, sockfp)
char *buf;
FILE *sockfp;
{
    return(SockWrite(fileno(sockfp), buf, strlen(buf)));
}

int SockWrite(socket,buf,len)
int socket;
char *buf;
int len;
{
    int n, rdlen = 0;
    
    while (len)
    {
        n = write(socket, buf, len);
        if (n <= 0)
            return -1;
        len -= n;
	rdlen += n;
	buf += n;
    }
    return rdlen;
}

static int sbuflen = 0;

static int SockInternalRead (socket,buf,len)
int socket;
char *buf;
int len;
{
   static char sbuf [INTERNAL_BUFSIZE];
   static char *bp;
   
   if (sbuflen <= 0) {
     /* buffer is empty; refresh. */
     if ((sbuflen = read(socket,sbuf,INTERNAL_BUFSIZE)) < 0) {
       if (errno == EINTR)
           return -1;
       perror("SockInternalRead: read");
       exit(9);
     }
     else
       bp = sbuf;
   }
   else
     ;  /* already some data in the buffer */

   /* can't get more than we have right now. */ 
   /* XXX -- should probably try to load any unused part of sbuf
             so that as much of 'len' as possible can be satisfied */
   if (len > sbuflen)
     len = sbuflen;
   else
     ;  /* wants no more than we already have */

   /* transfer to caller's buffer */
   if (len == 1) {
     /* special case:  if caller only wants one character, it probably
        costs a lot more to call bcopy than to do it ourselves. */
     *buf = *(bp++);
     sbuflen--;
   }
   else {
     bcopy(bp,buf,len);
     sbuflen -= len;
     bp += len;
   }
   return(len);
}

int SockRead(socket,buf,len)
int socket;
char *buf;
int len;
{
    int n;
    
    
    while (len)
    {
        n = SockInternalRead(socket, buf, len);
        if (n <= 0)
            return -1;
        len -= n;
        buf += n;
    }
    return 0;
}

int SockGets(buf, len, sockfp)
char *buf;
int len;
FILE *sockfp;
{
    int rdlen = 0;

    while (--len)
    {
        if (SockInternalRead(fileno(sockfp), buf, 1) != 1)
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
    return SockWrite(fileno(sockfp), buf, strlen(buf));

}

/* socket.c ends here */
