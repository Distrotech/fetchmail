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

#ifdef SUNOS
#include <memory.h>
#endif

int SockOpen(char *host, int clientPort)
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
        return -1;
    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0)
    {
	close(sock);
        return -1;
    }

    return(sock);
}


#if defined(HAVE_STDARG_H)
int SockPrintf(int sock, char* format, ...)
{
#else
int SockPrintf(sock,format,va_alist)
int sock;
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
    return SockWrite(sock, buf, strlen(buf));

}

int SockWrite(int sock, char *buf, int len)
{
    int n, wrlen = 0;

    while (len)
    {
        n = write(sock, buf, len);
        if (n <= 0)
            return -1;
        len -= n;
	wrlen += n;
	buf += n;
    }
    return wrlen;
}

int SockRead(int sock, char *buf, int len)
{
    char *p, *bp = buf;
    int n;

    if (--len < 1)
	return(-1);
    do {
	/* return value of 0 is EOF, < 0 is error */
	if ((n = recv(sock, bp, len, MSG_PEEK)) <= 0)
	    return(-1);
	if ((p = memchr(bp, '\n', n)) != NULL)
	{
	    if (read(sock, bp, ++p - bp) == -1)
		return(-1);
	    *p = '\0';
	    return strlen(buf);
	}
	if ((n = read(sock, bp, n)) == -1)
	    return(-1);
	bp += n;
	len -= n;
    } while 
	    (len);
    *bp = '\0';
    return strlen(buf);
}

int SockPeek(int sock)
/* peek at the next socket character without actually reading it */
{
    int n;
    char ch;

    if ((n = recv(sock, &ch, 1, MSG_PEEK)) == -1)
	return -1;
    else
	return(ch);
}

#ifdef MAIN
/*
 * Use the chargen service to test input beuffering directly.
 * You may have to uncomment the `chargen' service description in your
 * inetd.conf (and then SIGHUP inetd) for this to work. 
 */
main()
{
    int	 	sock = SockOpen("localhost", 19);
    char	buf[80];

    while (SockRead(sock, buf, sizeof(buf)-1))
	SockWrite(1, buf, strlen(buf));
}
#endif /* MAIN */

/* socket.c ends here */
