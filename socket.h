/*
 * socket.h -- declarations for socket library functions
 *
 * Design and implementation by Carl Harris <ceharris@mal.com>
 *
 * For license terms, see the file COPYING in this directory.
 */

#ifndef SOCKET__
#define SOCKET__

#if defined(HAVE_PROTOTYPES)
/*
Create a new client socket 
returns (FILE *)NULL on error 
*/
FILE *Socket(char *host, int clientPort);

/* 
Get a string terminated by an '\n', delete any '\r' and the '\n'.
Pass it a valid socket, a buffer for the string, and
the length of the buffer (including the trailing \0)
returns 0 for success. 
*/
int SockGets(char *buf, int len, FILE *sockfp);

/*
Write a chunk of bytes to the socket.
Returns 0 for success.
*/
int SockWrite(char *buf, int len, FILE *sockfp);

/* 
Send formatted output to the socket, followed
by a CR-LF.
Returns 0 for success.
*/
#if defined(HAVE_STDARG_H)
int SockPrintf(FILE *sockfp, char *format, ...) ;
#else
int SockPrintf();
#endif
 
#endif /* defined(HAVE_PROTOTYPES) */

#endif /* SOCKET__ */
