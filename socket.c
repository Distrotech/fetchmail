/* Copyright 1993-95 by Carl Harris, Jr.
 * All rights reserved
 *
 * Distribute freely, except: don't remove my name from the source or
 * documentation (don't take credit for my work), mark your changes (don't
 * get me blamed for your possible bugs), don't alter or remove this
 * notice.  May be sold if buildable source is provided to buyer.  No
 * warrantee of any kind, express or implied, is included with this
 * software; use at your own risk, responsibility for damages (if any) to
 * anyone resulting from the use of this software rests entirely with the
 * user.
 *
 * Send bug reports, bug fixes, enhancements, requests, flames, etc., and
 * I'll try to keep a version up to date.  I can be reached as follows:
 * Carl Harris <ceharris@mal.com>
 */


/***********************************************************************
  module:       socket.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  socket library functions

  $Log: socket.c,v $
  Revision 1.1  1996/06/28 14:48:28  esr
  Initial revision

  Revision 1.6  1995/08/14 18:36:48  ceharris
  Patches to support POP3's LAST command.
  Final revisions for beta3 release.

  Revision 1.5  1995/08/10 00:32:47  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.4  1995/08/09 01:33:05  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.3  1995/08/08 01:01:37  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

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
