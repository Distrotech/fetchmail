/*
 * socket.h -- declarations for socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#ifndef SOCKET__
#define SOCKET__

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

#endif /* SOCKET__ */
