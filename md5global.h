/*
 * md5global.h    Global declarations for MD5 module used by popclient
 *
 * $Log: md5global.h,v $
 * Revision 1.1  1996/06/28 14:36:11  esr
 * Initial revision
 *
 * Revision 1.2  1995/08/10 00:32:31  ceharris
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
 *
 */

#ifndef MD5GLOBAL_H__
#define MD5GLOBAL_H__ 
/* GLOBAL.H - RSAREF types and constants
 */

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already
  been defined with C compiler flags.
 */

#ifndef PROTOTYPES
#define PROTOTYPES HAVE_PROTOTYPES
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

#endif  /* MD5GLOBAL_H__ */
