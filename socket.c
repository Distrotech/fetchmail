/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       socket.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  socket library functions

 ***********************************************************************/

#include <config.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#if defined(STDC_HEADERS)
#include <string.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <stdlib.h>
#include <varargs.h>

#include "bzero.h"
#include "socket.h"

/* Size of buffer for internal buffering read function 
   don't increase beyond the maximum atomic read/write size for
   your sockets, or you'll take a potentially huge performance hit */

#define  INTERNAL_BUFSIZE	2048


int Socket(host, clientPort)
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
            return -1;
        memcpy(&ad.sin_addr, hp->h_addr, hp->h_length);
    }
    ad.sin_port = htons(clientPort);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return sock;
    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0)
        return -1;
    return sock;
}

int SockGets(socket,buf,len)
int socket;
char *buf;
int len;
{
    while (--len)
    {
        if (SockInternalRead(socket, buf, 1) != 1)
            return -1;
        if (*buf == '\n')
            break;
        if (*buf != '\r') /* remove all CRs */
            buf++;
    }
    *buf = 0;
    return 0;
}

int SockPuts(socket,buf)
int socket;
char *buf;
{
    int rc;
    
    if (rc = SockWrite(socket, buf, strlen(buf)))
        return rc;
    return SockWrite(socket, "\r\n", 2);
}

int SockWrite(socket,buf,len)
int socket;
char *buf;
int len;
{
    int n;
    
    while (len)
    {
        n = write(socket, buf, len);
        if (n <= 0)
            return -1;
        len -= n;
        buf += n;
    }
    return 0;
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

int SockInternalRead (socket,buf,len)
int socket;
char *buf;
int len;
{
   static int sbuflen = 0;
   static char sbuf [INTERNAL_BUFSIZE];
   static char *bp;
   
   if (sbuflen == 0) {
     /* buffer is empty; refresh. */
     if ((sbuflen = read(socket,sbuf,INTERNAL_BUFSIZE)) < 0) {
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


int SockPrintf(socket,format,va_alist)
int socket;
char *format;
va_dcl {

    va_list ap;
    char buf[8192];
    
    va_start(ap);
    vsprintf(buf, format, ap);
    va_end(ap);
    return SockWrite(socket, buf, strlen(buf));
}
