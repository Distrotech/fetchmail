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
#define		MSGBUFSIZE	2048   	/* size of message read buffer */
#define		HOSTLEN		128	/* max hostname length */
#define		USERNAMELEN	32	/* max user-length */
#define		PASSWORDLEN	MAX_PASSWORD_LENGTH
#define		FOLDERLEN	256     /* max folder name length */
#define		DIGESTLEN	33	/* length of MD5 digest */
#define		MDALEN		256	/* length of delivery agent command */
#define		IDLEN		128	/* length of UIDL message ID */

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
#define         PS_SMTP         9       /* SMTP error */
#define		PS_UNDEFINED	10	/* something I hadn't thought of */

/* output noise level */
#define         O_SILENT	0	/* mute, max squelch, etc. */
#define		O_NORMAL	1	/* user-friendly */
#define		O_VERBOSE	2	/* excessive */

/* output sink type */
#define		TO_SMTP		1	/* use SMTP forwarding */
#define		TO_FOLDER	2	/* use a mailbox */
#define		TO_STDOUT	3	/* use stdout */
#define		TO_MDA		4	/* use agent */

struct hostrec
{
  char servername [HOSTLEN+1];
  char localname [USERNAMELEN+1];
  char remotename [USERNAMELEN+1];
  char password [PASSWORDLEN+1];
  char rpopid [PASSWORDLEN+1];
  char userfolder [FOLDERLEN+1];
  char remotefolder [FOLDERLEN];
  char smtphost[HOSTLEN+1];
  char mda [MDALEN+1];
  int keep;
  int protocol;
  int fetchall;
  int flush;
  int norewrite;
  int port;

  /* state used for tracking UIDL ids */
  char lastid [IDLEN];

  /* dependent on the above members */
  int output;
  struct hostrec *next;

#if defined(HAVE_APOP_SUPPORT)
  /* internal use only */ 
  char digest [DIGESTLEN];
#endif
};

struct method
{
    char *name;			/* protocol name */
    int	port;			/* service port */
    int tagged;			/* if true, generate & expect command tags */
    int delimited;		/* if true, accept "." message delimiter */
    int (*parse_response)();	/* response_parsing function */
    int (*getauth)();		/* authorization fetcher */
    int (*getrange)();		/* get message range to fetch */
    int (*fetch)();		/* fetch a given message */
    int (*trail)();		/* eat trailer of a message */
    char *delete_cmd;		/* delete command */
    char *expunge_cmd;		/* expunge command */
    char *exit_cmd;		/* exit command */
};

#define TAGLEN	5
extern char tag[TAGLEN];

/* controls the detail level of status/progress messages written to stderr */
extern int outlevel;    	/* see the O_.* constants above */
extern int yydebug;		/* enable parse debugging */

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern char *logfile;		/* log file for daemon mode */
extern int quitmode;		/* if --quit was set */

/* miscellaneous global controls */
extern char *poprcfile;		/* path name of rc file */
extern char *idfile;		/* path name of id file */
extern int linelimit;		/* limit # lines retrieved per site */
extern int versioninfo;		/* emit only version info */

#ifdef HAVE_PROTOTYPES

int gen_ok (char *buf, int socket);
void gen_send ();
int gen_transact ();

/* prototypes for globally callable functions */
int doPOP2 (struct hostrec *); 
int doPOP3 (struct hostrec *);

int parsecmdline (int, char **, struct hostrec *);
int setdefaults (struct hostrec *);
char *getnextserver (int argc, char **, int *);
int openuserfolder (struct hostrec *);
int closeuserfolder (int);
int openmailpipe (struct hostrec *);
int closemailpipe (int);
char *MD5Digest (char *);
void append_server_names(int *, char **, int);
int daemonize(const char *, void (*)(int));

#else

char *getnextserver();
char *MD5Digest ();
void append_server_names ();
int daemonize ();

#endif

