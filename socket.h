/*
 * socket.h -- declarations for socket library functions
 *
 * Design and implementation by Carl Harris <ceharris@mal.com>
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

/* Ship a character array to the socket */
#define SockWrite(buf, len, sockfp)	fwrite(buf, 1, len, sockfp)

/* 
Send formatted output to the socket, followed
by a CR-LF.  Returns 0 for success.
*/
#define SockPrintf	fprintf

#endif /* SOCKET__ */
