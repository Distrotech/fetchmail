/*
 * socket.h -- declarations for socket library functions
 *
 * For license terms, see the file COPYING in this directory.
 */

#ifndef SOCKET__
#define SOCKET__

/* Create a new client socket; returns (FILE *)NULL on error */
FILE *sockopen(char *host, int clientPort);

#endif /* SOCKET__ */
