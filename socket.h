/*
 * socket.h -- declarations for socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#ifndef SOCKET__
#define SOCKET__

/* Create a new client socket; returns (FILE *)NULL on error */
int SockOpen(const char *host, int clientPort);

/* 
Get a string terminated by an '\n' (matches interface of fgets).
Pass it a valid socket, a buffer for the string, and
the length of the buffer (including the trailing \0)
returns buffer on success, NULL on failure. 
*/
int SockRead(int sock, char *buf, int len);

/*
 * Peek at the next socket character without actually reading it.
 */
int SockPeek(int sock);

/*
Write a chunk of bytes to the socket (matches interface of fwrite).
Returns number of bytes successfully written.
*/
int SockWrite(int sock, char *buf, int size);

/* 
Send formatted output to the socket (matches interface of fprintf).
Returns number of bytes successfully written.
*/
#if defined(HAVE_STDARG_H)
int SockPrintf(int sock, char *format, ...) ;
#else
int SockPrintf();
#endif
 
#endif /* SOCKET__ */
