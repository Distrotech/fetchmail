/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       popclient.h
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  global constant, type, and variable definitions.

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
#define		PS_EXCLUDE	8	/* exclusion error */
#define		PS_UNDEFINED	9	/* something I hadn't thought of */

/* output noise level */
#define         O_SILENT	0	/* mute, max squelch, etc. */
#define		O_NORMAL	1	/* user-friendly */
#define		O_VERBOSE	2	/* excessive */

/* output sink type */
#define		TO_FOLDER	1	/* use a mailbox */
#define		TO_STDOUT	2	/* use stdout */
#define		TO_MDA		3	/* use agent */

struct optrec {
  int keep;
  int protocol;
  int limit;
  int fetchall;
  int flush;
  int output;
  char servername [HOSTLEN];
  char localname [USERNAMELEN];
  char remotename [USERNAMELEN];
  char password [PASSWORDLEN];
#if defined(HAVE_APOP_SUPPORT)
  char digest [DIGESTLEN];
#endif
  char userfolder [FOLDERLEN];
  char remotefolder [FOLDERLEN];
  char mda [MDALEN];
  struct optrec *next;
};


/* .poprc records are passed in this structure type */
struct prc_server {
  char *server;
  int protocol;
  char *remotename;
  char *password;
  char *remotefolder;
  char *userfolder;
  char *mda;
  int keep;
  int flush;
  int fetchall;
};


/* controls the detail level of status/progress messages written to stderr */
extern int outlevel;    	/* see the O_.* constants above */
extern int yydebug;		/* enable parse debugging */

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern char *logfile;		/* log file for daemon mode */
extern int quitmode;		/* if --quit was set */

/* miscellaneous global controls */
extern char *poprcfile;		/* path name of rc file */
extern int linelimit;		/* limit # lines retrieved per site */
extern int versioninfo;		/* emit only version info */

#ifdef HAVE_PROTOTYPES

/* prototypes for globally callable functions */
int doPOP2 (struct optrec *options); 
int doPOP3 (struct optrec *options);

int parsecmdline (int argc, char **argv, struct optrec *options);
int setdefaults (struct optrec *options);
char *getnextserver (int argc, char **argv, int *optind);
int openuserfolder (struct optrec *options);
int closeuserfolder (int fd);
int openmailpipe (struct optrec *options);
int closemailpipe (int fd);
char *MD5Digest (char *);
void reply_hack(char *buf, const char *host);
void append_server_names(int *pargc, char **argv);
int daemonize(const char *logfile, void (*)(void));

#else

char *getnextserver();
char *MD5Digest ();
void reply_hack ();
void append_server_names ();
int daemonize ();

#endif

