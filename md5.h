/*
 * md5.h  header file for MD5 module used by popclient
 *
 * $Log: md5.h,v $
 * Revision 1.1  1996/06/28 14:34:58  esr
 * Initial revision
 *
 * Revision 1.2  1995/08/10 00:32:28  ceharris
 * Preparation for 3.0b3 beta release:
 * -	added code for --kill/--keep, --limit, --protocol, --flush
 * 	options; --pop2 and --pop3 options now obsoleted by --protocol.
 * - 	added support for APOP authentication, including --with-APOP
 * 	argument for configure.
 * -	provisional and broken support for RPOP
 * -	added buffering to SockGets and SockRead functions.
 * -	fixed problem of command-line options not being correctly
 * 	carried into the merged options record.
 *
 * Revision 1.1  1995/08/09 14:27:22  ceharris
 * First revision popclient MD5 support for APOP.  The MD5 code is
 * provided by RSA Data Security.  See notice below.
 *
 *
 */

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef MD5_H__
#define MD5_H__

#include "md5global.h"

/* MD5 context. */
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init PROTO_LIST ((MD5_CTX *));
void MD5Update PROTO_LIST
  ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));
#endif /* MD5_H__ */
