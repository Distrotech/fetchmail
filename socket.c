/*
 * socket.c -- socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
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

#ifndef INET_ATON
#ifndef  INADDR_NONE
#ifdef   INADDR_BROADCAST
#define  INADDR_NONE	INADDR_BROADCAST
#else
#define	 INADDR_NONE	-1
#endif
#endif
#endif /* INET_ATON */

#ifdef SUNOS
#include <memory.h>
#endif

int SockOpen(char *host, int clientPort)
{
    int sock;
#ifndef INET_ATON
    unsigned long inaddr;
#endif /* INET_ATON */
    struct sockaddr_in ad;
    struct hostent *hp;

    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;

    /* we'll accept a quad address */
#ifndef INET_ATON
    inaddr = inet_addr(host);
    if (inaddr != INADDR_NONE)
        memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
    else
#else
    if (!inet_aton(host, &ad.sin_addr))
#endif /* INET_ATON */
    {
        hp = gethostbyname(host);

	/*
	 * Add a check to make sure the address has a valid IPv4 or IPv6
	 * length.  This prevents buffer spamming by a broken DNS.
	 */
        if (hp == NULL || (hp->h_length != 4 && hp->h_length != 8))
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
#ifdef HAVE_VSNPRINTF
    vsnprintf(buf, sizeof(buf), format, ap);
#else
    vsprintf(buf, format, ap);
#endif
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
    char *newline, *bp = buf;
    int n;

    if (--len < 1)
	return(-1);
    do {
	/* 
	 * The reason for these gymnastics is that we want two things:
	 * (1) to read \n-terminated lines,
	 * (2) to return the true length of data read, even if the
	 *     data coming in has embedded NULS.
	 */
	if ((n = recv(sock, bp, len, MSG_PEEK)) <= 0)
	    return(-1);
	if ((newline = memchr(bp, '\n', n)) != NULL)
	    n = newline - bp + 1;
	if ((n = read(sock, bp, n)) == -1)
	    return(-1);
	bp += n;
	len -= n;
    } while 
	    (!newline && len);
    *bp = '\0';
    return bp - buf;
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
