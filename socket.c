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

#ifndef  INADDR_NONE
#ifdef   INADDR_BROADCAST
#define  INADDR_NONE	INADDR_BROADCAST
#else
#define	 INADDR_NONE	-1
#endif
#endif

#define  INTERNAL_BUFSIZE	2048

FILE *Socket(host, clientPort)
char *host;
int clientPort;
{
    int sock;
    unsigned long inaddr;
    struct sockaddr_in ad;
    struct hostent *hp;
    FILE *sockfp;

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

    sockfp = fdopen(sock, "r+");
    setvbuf(sockfp, NULL, _IOLBF, INTERNAL_BUFSIZE);
    return sockfp;
}

/* socket.c ends here */
