/* Copyright 1993-95 by Carl Harris, Jr.
 * All rights reserved
 *
 * Distribute freely, except: don't remove my name from the source or
 * documentation (don't take credit for my work), mark your changes (don't
 * get me blamed for your possible bugs), don't alter or remove this
 * notice.  May be sold if buildable source is provided to buyer.  No
 * warrantee of any kind, express or implied, is included with this
 * software; use at your own risk, responsibility for damages (if any) to
 * anyone resulting from the use of this software rests entirely with the
 * user.
 *
 * Send bug reports, bug fixes, enhancements, requests, flames, etc., and
 * I'll try to keep a version up to date.  I can be reached as follows:
 * Carl Harris <ceharris@mal.com>
 */


/***********************************************************************
  module:       popclient.h
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  global constant, type, and variable definitions.

  $Log: fetchmail.h,v $
  Revision 1.2  1996/06/26 19:08:59  esr
  This is what I sent Harris.

  Revision 1.1  1996/06/24 18:14:08  esr
  Initial revision

  Revision 1.6  1995/09/07 22:37:35  ceharris
  Preparation for 3.0b4 release.

  Revision 1.5  1995/08/14 18:36:44  ceharris
  Patches to support POP3's LAST command.
  Final revisions for beta3 release.

  Revision 1.4  1995/08/10 00:32:40  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.3  1995/08/09 01:32:57  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.2  1995/08/08 01:01:27  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

 ***********************************************************************/



/* definitions for buffer sizes -- somewhat arbitrary */
#define		POPBUFSIZE	512	/* per RFC 937 */
#define		MSGBUFSIZE	1024   	/* size of message read buffer */
#define		HOSTLEN		128	/* max hostname length */
#define		USERNAMELEN	32	/* max user-length */
#define		PASSWORDLEN	MAX_PASSWORD_LENGTH
#define		FOLDERLEN	256     /* max folder name length */
#define		DIGESTLEN	33	/* length of MD5 digest */
#define		MDALEN		33	/* length of delivery agent command */

/* exit code values */
#define		PS_SUCCESS	0	/* successful receipt of messages */
#define		PS_NOMAIL       1	/* no mail available */
#define		PS_SOCKET	2	/* socket I/O woes */
#define		PS_AUTHFAIL	3	/* user authorization failed */
#define		PS_PROTOCOL	4	/* protocol violation */
#define		PS_SYNTAX	5	/* command-line syntax error */
#define		PS_IOERR	6	/* local folder I/O woes */
#define		PS_ERROR	7	/* some kind of POP3 error condition */
#define		PS_UNDEFINED	9	/* something I hadn't thought of */

/* output noise level */
#define         O_SILENT	0	/* mute, max squelch, etc. */
#define		O_NORMAL	1	/* user-friendly */
#define		O_VERBOSE	2	/* excessive */

/* output sink type */
#define		TO_FOLDER	1	/* use a mailbox */
#define		TO_STDOUT	2	/* use stdout */
#define		TO_MDA		3	/* use agent */

/* Command-line arguments are passed in this structure type */
struct optrec {
  int versioninfo;
  int keep;
  int verbose;
  int whichpop;
  int silent;
  int limit;
  int fetchall;
  int flush;
  int output;
  char loginid [USERNAMELEN];
  char *poprcfile;
  char username [USERNAMELEN];
  char password [PASSWORDLEN];
#if defined(HAVE_APOP_SUPPORT)
  char digest [DIGESTLEN];
#endif
  char userfolder [FOLDERLEN];
  char remotefolder [FOLDERLEN];
  char mda [MDALEN];
};


/* .poprc records are passed in this structure type */
struct prc_server {
  char *server;
  int protocol;
  char *username;
  char *password;
  char *remotefolder;
  char *userfolder;
  char *mda;
  int keep;
  int flush;
  int fetchall;
};


/* Controls the detail of status/progress messages written to stderr */
extern int outlevel;    /* see the O_.* constants above */
extern int yydebug;	/* enable parse debugging */ 

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern char *logfile;		/* log file for daemon mode */

extern char *prc_pathname;	/* path name of rc file */

#ifdef HAVE_PROTOTYPES

/* prototypes for globally callable functions */
int doPOP2 (char *servername, struct optrec *options); 
int doPOP3 (char *servername, struct optrec *options);

int parsecmdline (int argc, char **argv, struct optrec *options);
int setdefaults (struct optrec *options);
char *getnextserver (int argc, char **argv, int *optind);
int openuserfolder (struct optrec *options);
int closeuserfolder (int fd);
int openmailpipe (struct optrec *options);
int closemailpipe (int fd);
char *MD5Digest (char *);
char *prc_getpathname (struct optrec *cmd_opts, struct optrec *def_opts);
void reply_hack(char *buf, const char *host);
void append_server_names(int *pargc, char **argv);
int daemonize(const char *logfile);

#else

char *getnextserver();
char *MD5Digest ();
char *prc_getpathname();
void reply_hack ();
void append_server_names ();
int daemonize ();

#endif

