/*
 * socket.c -- socket library functions
 *
 * Copyright 1998 by Eric S. Raymond.
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif /* HAVE_MEMORY_H */
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
#include "fetchmail.h"
#include "i18n.h"

/* We need to define h_errno only if it is not already */
#ifndef h_errno

#ifdef HAVE_RES_SEARCH
/* some versions of FreeBSD should declare this but don't */
extern int h_errno;
#else
/* pretend we have h_errno to avoid some #ifdef's later */
static int h_errno;
#endif

#endif /* ndef h_errno */

#if NET_SECURITY
#include <net/security.h>
#endif /* NET_SECURITY */

#ifdef HAVE_SOCKETPAIR
static int handle_plugin(const char *host,
			 const char *service, const char *plugin)
/* get a socket mediated through a given external command */
{
    int fds[2];
    if (socketpair(AF_UNIX,SOCK_STREAM,0,fds))
    {
	report(stderr, _("fetchmail: socketpair failed\n"));
	return -1;
    }
    switch (fork()) {
	case -1:
		/* error */
		report(stderr, _("fetchmail: fork failed\n"));
		return -1;
		break;
	case 0:	/* child */
		/* fds[1] is the parent's end; close it for proper EOF
		** detection */
		(void) close(fds[1]);
		if ( (dup2(fds[0],0) == -1) || (dup2(fds[0],1) == -1) ) {
			report(stderr, _("dup2 failed\n"));
			exit(1);
		}
		/* fds[0] is now connected to 0 and 1; close it */
		(void) close(fds[0]);
		if (outlevel >= O_VERBOSE)
		    report(stderr, _("running %s %s %s\n"), plugin, host, service);
		execlp(plugin,plugin,host,service,0);
		report(stderr, _("execl(%s) failed\n"), plugin);
		exit(0);
		break;
	default:	/* parent */
		/* NOP */
		break;
    }
    /* fds[0] is the child's end; close it for proper EOF detection */
    (void) close(fds[0]);
    return fds[1];
}
#endif /* HAVE_SOCKETPAIR */

#ifdef __UNUSED__
#include <sys/time.h>

int SockCheckOpen(int fd)
/* poll given socket; is it selectable? */
{
    fd_set r, w, e;
    int rt;
    struct timeval tv;
  
    for (;;) 
    {
	FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&e);
	FD_SET(fd, &e);
    
	tv.tv_sec = 0; tv.tv_usec = 0;
	rt = select(fd+1, &r, &w, &e, &tv);
	if (rt == -1 && (errno != EAGAIN && errno != EINTR))
	    return 0;
	if (rt != -1)
	    return 1;
    }
}
#endif /* __UNUSED__ */

#if INET6_ENABLE
int SockOpen(const char *host, const char *service, const char *options,
	     const char *plugin)
{
    struct addrinfo *ai, req;
    int i;
#if NET_SECURITY
    void *request = NULL;
    int requestlen;
#endif /* NET_SECURITY */

#ifdef HAVE_SOCKETPAIR
    if (plugin)
	return handle_plugin(host,service,plugin);
#endif /* HAVE_SOCKETPAIR */
    memset(&req, 0, sizeof(struct addrinfo));
    req.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, service, &req, &ai)) {
	report(stderr, _("fetchmail: getaddrinfo(%s.%s)\n"), host,service);
	return -1;
    };

#if NET_SECURITY
    if (!options)
	requestlen = 0;
    else
	if (net_security_strtorequest((char *)options, &request, &requestlen))
	    goto ret;

    i = inner_connect(ai, request, requestlen, NULL, NULL, "fetchmail", NULL);
    if (request)
	free(request);

 ret:
#else /* NET_SECURITY */
#ifdef HAVE_INNER_CONNECT
    i = inner_connect(ai, NULL, 0, NULL, NULL, "fetchmail", NULL);
#else
    i = socket(ai->ai_family, ai->ai_socktype, 0);
    if (i < 0) {
	freeaddrinfo(ai);
	return -1;
    }
    if (connect(i, (struct sockaddr *) ai->ai_addr, ai->ai_addrlen) < 0) {
	freeaddrinfo(ai);
	SockClose(i);
	return -1;
    }
#endif
#endif /* NET_SECURITY */

    freeaddrinfo(ai);

    return i;
};
#else /* INET6_ENABLE */
#ifndef HAVE_INET_ATON
#ifndef  INADDR_NONE
#ifdef   INADDR_BROADCAST
#define  INADDR_NONE	INADDR_BROADCAST
#else
#define	 INADDR_NONE	-1
#endif
#endif
#endif /* HAVE_INET_ATON */

int SockOpen(const char *host, int clientPort, const char *options,
	     const char *plugin)
{
    int sock = -1;	/* pacify -Wall */
#ifndef HAVE_INET_ATON
    unsigned long inaddr;
#endif /* HAVE_INET_ATON */
    struct sockaddr_in ad, **pptr;
    struct hostent *hp;

#ifdef HAVE_SOCKETPAIR
    if (plugin) {
      char buf[10];
      sprintf(buf,"%d",clientPort);
      return handle_plugin(host,buf,plugin);
    }
#endif /* HAVE_SOCKETPAIR */

    memset(&ad, 0, sizeof(ad));
    ad.sin_family = AF_INET;

    /* we'll accept a quad address */
#ifndef HAVE_INET_ATON
    inaddr = inet_addr(host);
    if (inaddr != INADDR_NONE)
    {
        memcpy(&ad.sin_addr, &inaddr, sizeof(inaddr));
#else
    if (inet_aton(host, &ad.sin_addr))
    {
#endif /* HAVE_INET_ATON */
        ad.sin_port = htons(clientPort);

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            h_errno = 0;
            return -1;
        }
        if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) < 0)
        {
            int olderr = errno;
            SockClose(sock);
            h_errno = 0;
            errno = olderr;
            return -1;
        }
#ifndef HAVE_INET_ATON
    }
#else
    }
#endif /* HAVE_INET_ATON */
    else {
        hp = gethostbyname(host);

        if (hp == NULL)
	{
	    errno = 0;
	    return -1;
	}
	/*
	 * Add a check to make sure the address has a valid IPv4 or IPv6
	 * length.  This prevents buffer spamming by a broken DNS.
	 */
	if(hp->h_length != 4 && hp->h_length != 8)
	{
	    h_errno = errno = 0;
	    report(stderr, 
		   _("fetchmail: illegal address length received for host %s\n"),host);
	    return -1;
	}
	/*
	 * Try all addresses of a possibly multihomed host until we get
	 * a successful connect or until we run out of addresses.
	 */
	pptr = (struct sockaddr_in **)hp->h_addr_list;
	for(; *pptr != NULL; pptr++)
	{
	    sock = socket(AF_INET, SOCK_STREAM, 0);
	    if (sock < 0)
	    {
		h_errno = 0;
		return -1;
	    }
	    ad.sin_port = htons(clientPort);
	    memcpy(&ad.sin_addr, *pptr, sizeof(struct in_addr));
	    if (connect(sock, (struct sockaddr *) &ad, sizeof(ad)) == 0)
		break; /* success */
	    SockClose(sock);
	    memset(&ad, 0, sizeof(ad));
	    ad.sin_family = AF_INET;
	}
	if(*pptr == NULL)
	{
	    int olderr = errno;
	    SockClose(sock);
	    h_errno = 0;
	    errno = olderr;
	    return -1;
	}
    }
    return(sock);
}
#endif /* INET6_ENABLE */


#if defined(HAVE_STDARG_H)
int SockPrintf(int sock, const char* format, ...)
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

#ifdef SSL_ENABLE
#include "ssl.h"
#include "err.h"
#include "pem.h"
#include "x509.h"

static	SSL_CTX *_ctx = NULL;
static	SSL *_ssl_context[FD_SETSIZE];

SSL	*SSLGetContext( int );
#endif /* SSL_ENABLE */

int SockWrite(int sock, char *buf, int len)
{
    int n, wrlen = 0;
#ifdef	SSL_ENABLE
    SSL *ssl;
#endif

    while (len)
    {
#ifdef SSL_ENABLE
	if( NULL != ( ssl = SSLGetContext( sock ) ) )
		n = SSL_write(ssl, buf, len);
	else
        	n = write(sock, buf, len);
#else
        n = write(sock, buf, len);
#endif
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
#ifdef	SSL_ENABLE
    SSL *ssl;
#endif

    if (--len < 1)
	return(-1);
    do {
	/* 
	 * The reason for these gymnastics is that we want two things:
	 * (1) to read \n-terminated lines,
	 * (2) to return the true length of data read, even if the
	 *     data coming in has embedded NULS.
	 */
#ifdef	SSL_ENABLE
	if( NULL != ( ssl = SSLGetContext( sock ) ) ) {
		/* Hack alert! */
		/* OK...  SSL_peek works a little different from MSG_PEEK
			Problem is that SSL_peek can return 0 if there
			is no data currently available.  If, on the other
			hand, we loose the socket, we also get a zero, but
			the SSL_read then SEGFAULTS!  To deal with this,
			we'll check the error code any time we get a return
			of zero from SSL_peek.  If we have an error, we bail.
			If we don't, we read one character in SSL_read and
			loop.  This should continue to work even if they
			later change the behavior of SSL_peek
			to "fix" this problem...  :-(	*/
		if ((n = SSL_peek(ssl, bp, len)) < 0) {
			return(-1);
		}
		if( 0 == n ) {
			/* SSL_peek says no data...  Does he mean no data
			or did the connection blow up?  If we got an error
			then bail! */
			if( 0 != ( n = ERR_get_error() ) ) {
				return -1;
			}
			/* We didn't get an error so read at least one
				character at this point and loop */
			n = 1;
			/* Make sure newline start out NULL!
			 * We don't have a string to pass through
			 * the strchr at this point yet */
			newline = NULL;
		} else if ((newline = memchr(bp, '\n', n)) != NULL)
			n = newline - bp + 1;
		if ((n = SSL_read(ssl, bp, n)) == -1) {
			return(-1);
		}
		/* Check for case where our single character turned out to
		 * be a newline...  (It wasn't going to get caught by
		 * the strchr above if it came from the hack...  ). */
		if( NULL == newline && 1 == n && '\n' == *bp ) {
			/* Got our newline - this will break
				out of the loop now */
			newline = bp;
		}
	} else {
		if ((n = recv(sock, bp, len, MSG_PEEK)) <= 0)
			return(-1);
		if ((newline = memchr(bp, '\n', n)) != NULL)
			n = newline - bp + 1;
		if ((n = read(sock, bp, n)) == -1)
			return(-1);
	}
#else
	if ((n = recv(sock, bp, len, MSG_PEEK)) <= 0)
	    return(-1);
	if ((newline = memchr(bp, '\n', n)) != NULL)
	    n = newline - bp + 1;
	if ((n = read(sock, bp, n)) == -1)
	    return(-1);
#endif
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
#ifdef	SSL_ENABLE
    SSL *ssl;
#endif

#ifdef	SSL_ENABLE
	if( NULL != ( ssl = SSLGetContext( sock ) ) ) {
		n = SSL_peek(ssl, &ch, 1);
		if( 0 == n ) {
			/* This code really needs to implement a "hold back"
			 * to simulate a functioning SSL_peek()...  sigh...
			 * Has to be coordinated with the read code above.
			 * Next on the list todo...	*/

			/* SSL_peek says no data...  Does he mean no data
			or did the connection blow up?  If we got an error
			then bail! */
			if( 0 != ( n = ERR_get_error() ) ) {
				return -1;
			}

			/* Haven't seen this case actually occur, but...
			   if the problem in SockRead can occur, this should
			   be possible...  Just not sure what to do here.
			   This should be a safe "punt" the "peek" but don't
			   "punt" the "session"... */

			return 0;	/* Give him a '\0' character */
		}
	} else {
    		n = recv(sock, &ch, 1, MSG_PEEK);
	}
#else
    	n = recv(sock, &ch, 1, MSG_PEEK);
#endif
	if (n == -1)
		return -1;
	else
		return(ch);
}

#ifdef SSL_ENABLE

static	char *_ssl_server_cname = NULL;

SSL *SSLGetContext( int sock )
{
	/* If SSLOpen has never initialized - just return NULL */
	if( NULL == _ctx )
		return NULL;

	if( sock < 0 || sock > FD_SETSIZE )
		return NULL;
	return _ssl_context[sock];
}


int SSL_verify_callback( int ok_return, X509_STORE_CTX *ctx )
{
	char buf[260];
	char cbuf[260];
	char ibuf[260];
	char *str_ptr;
	X509 *x509_cert;
	int err, depth;

	x509_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	X509_NAME_oneline(X509_get_subject_name(x509_cert), buf, 256);
	X509_NAME_oneline(X509_get_issuer_name(x509_cert), ibuf, 256);

	/* Just to be sure those buffers are terminated...  I think the
		X509 libraries do, but... */
	buf[256] = ibuf[256] = '\0';

	if (depth == 0) {
		if( ( str_ptr = strstr( ibuf, "/O=" ) ) ) {
			str_ptr += 3;
			strcpy( cbuf, str_ptr );
			if( ( str_ptr = strchr(cbuf, '/' ) ) ) {
				*str_ptr = '\0';
			}
			if (outlevel == O_VERBOSE)
				report(stdout, "Issuer Organization: %s\n", cbuf );
		} else {
			if (outlevel == O_VERBOSE)
				report(stdout, "Unknown Organization\n", cbuf );
		}
		if( ( str_ptr = strstr( ibuf, "/CN=" ) ) ) {
			str_ptr += 4;
			strcpy( cbuf, str_ptr );
			if( ( str_ptr = strchr(cbuf, '/' ) ) ) {
				*str_ptr = '\0';
			}
			if (outlevel == O_VERBOSE)
				report(stdout, "Issuer CommonName: %s\n", cbuf );
		} else {
			if (outlevel == O_VERBOSE)
				report(stdout, "Unknown Issuer CommonName\n", cbuf );
		}
		if( ( str_ptr = strstr( buf, "/CN=" ) ) ) {
			str_ptr += 4;
			strcpy( cbuf, str_ptr );
			if( ( str_ptr = strchr(cbuf, '/' ) ) ) {
				*str_ptr = '\0';
			}
			if (outlevel == O_VERBOSE)
				report(stdout, "Server CommonName: %s\n", cbuf );
			/* Should we have some wildcarding here? */
			if ( NULL != _ssl_server_cname
			     && 0 != strcmp( cbuf, _ssl_server_cname ) ) {
				report(stdout,
				       "Server CommonName mismatch: %s != %s\n",
				       cbuf, _ssl_server_cname );
			}
		} else {
			if (outlevel == O_VERBOSE)
				report(stdout, "Unknown Server CommonName\n", cbuf );
		}
	}

	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
		report(stdout, "unknown issuer= %s", buf);
		break;
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		report(stderr, "Server Certificate not yet valid");
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		report(stderr, "Server Certificate expired");
		break;
	}
	/* We are not requiring or validating server or issuer id's as yet */
	/* Always return OK from here */
	ok_return = 1;
	return( ok_return );
}


/* performs initial SSL handshake over the connected socket
 * uses SSL *ssl global variable, which is currently defined
 * in this file
 */
int SSLOpen(int sock, char *mycert, char *mykey, char *servercname )
{
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	
	if( sock < 0 || sock > FD_SETSIZE ) {
		report(stderr, "File descriptor out of range for SSL" );
		return( -1 );
	}

	if( ! _ctx ) {
		/* Be picky and make sure the memory is cleared */
		memset( _ssl_context, 0, sizeof( _ssl_context ) );
		_ctx = SSL_CTX_new(SSLv23_client_method());
		if(_ctx == NULL) {
			ERR_print_errors_fp(stderr);
			return(-1);
		}
	}
	
	_ssl_context[sock] = SSL_new(_ctx);
	
	if(_ssl_context[sock] == NULL) {
		ERR_print_errors_fp(stderr);
		return(-1);
	}
	
	/* This static is for the verify callback */
	_ssl_server_cname = servercname;

        SSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, SSL_verify_callback);

	if( mycert || mykey ) {

	/* Ok...  He has a certificate file defined, so lets declare it.  If
	 * he does NOT have a separate certificate and private key file then
	 * assume that it's a combined key and certificate file.
	 */
		if( !mykey )
			mykey = mycert;
		if( !mycert )
			mycert = mykey;
        	SSL_use_certificate_file(_ssl_context[sock], mycert, SSL_FILETYPE_PEM);
        	SSL_use_RSAPrivateKey_file(_ssl_context[sock], mykey, SSL_FILETYPE_PEM);
	}

	SSL_set_fd(_ssl_context[sock], sock);
	
	if(SSL_connect(_ssl_context[sock]) == -1) {
		ERR_print_errors_fp(stderr);
		return(-1);
	}
	
	return(0);
}
#endif

int SockClose(int sock)
/* close a socket gracefully */
{
    char ch;
#ifdef	SSL_ENABLE
    SSL *ssl;

    if( NULL != ( ssl = SSLGetContext( sock ) ) ) {
        /* Clean up the SSL stack */
        SSL_free( _ssl_context[sock] );
        _ssl_context[sock] = NULL;
    }
#endif

    /* Half-close the connection first so the other end gets notified.
     *
     * This stops sends but allows receives (effectively, it sends a
     * TCP <FIN>).  We ignore the return from this function because
     * some older BSD-based implementations fail shutdown() if a TCP
     * reset has been recieved.  In any case, if it fails it means the
     * connection is already closed anyway, so it doesn't matter.
     */
    shutdown(sock, 1);

    /* If there is any data still waiting in the queue, discard it.
     * Call recv() until either it returns 0 (meaning we received a FIN)
     * or any error occurs.  This makes sure all data sent by the other
     * side is acknowledged at the TCP level.
     */
    if (recv(sock, &ch, 1, MSG_PEEK) > 0)
	while (recv(sock, &ch, 1, MSG_NOSIGNAL) > 0)
	    continue;

    /* if there's an error closing at this point, not much we can do */
    return(close(sock));	/* this is guarded */
}

#ifdef MAIN
/*
 * Use the chargen service to test input buffering directly.
 * You may have to uncomment the `chargen' service description in your
 * inetd.conf (and then SIGHUP inetd) for this to work.  */
main()
{
    int	 	sock = SockOpen("localhost", 19, NULL);
    char	buf[80];

    while (SockRead(sock, buf, sizeof(buf)-1))
	SockWrite(1, buf, strlen(buf));
    SockClose(sock);
}
#endif /* MAIN */

/* socket.c ends here */
