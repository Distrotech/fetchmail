/*
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       fetchmail.h
  project:      fetchmail
  programmer:   Eric S. Raymond <esr@thyrsus.com>
  description:  global constant, type, and variable definitions.

 ***********************************************************************/

/* constants designating the various supported protocols */
#define		P_AUTO		0
#define		P_POP2		2
#define		P_POP3		3
#define		P_IMAP		4
#define		P_APOP		5

#define		KPOP_PORT	1109

/* authentication types */
#define		A_PASSWORD	0	/* passwords in cleartext */
#define		A_KERBEROS	1	/* get Kerberos V4 ticket */

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
#define		PS_IOERR	6	/* bad permissions on rc file */
#define		PS_ERROR	7	/* protocol error */
#define		PS_EXCLUDE	8	/* exclusion error */
#define         PS_SMTP         9       /* SMTP error */
#define		PS_UNDEFINED	10	/* something I hadn't thought of */

/* output noise level */
#define         O_SILENT	0	/* mute, max squelch, etc. */
#define		O_NORMAL	1	/* user-friendly */
#define		O_VERBOSE	2	/* excessive */

#define		SIZETICKER	1024	/* print 1 dot per this many bytes */

struct idlist
{
    char *id;
    union
    {
	int num;
	char *id2;
    } val;
    struct idlist *next;
};

struct hostrec
{
    /* per-host data */
    char servername [HOSTLEN+1];
    char remotename [USERNAMELEN+1];
    char password [PASSWORDLEN+1];
    char mailbox [FOLDERLEN];
    char smtphost[HOSTLEN+1];
    char mda [MDALEN+1];
    struct idlist *localnames;
    int protocol;
    int port;
    int authenticate;
    int timeout;

    /* MDA arguments */
    char *mda_argv[32];
    char mdabuf[MDALEN+1];

    /* control flags */
    int keep;
    int fetchall;
    int flush;
    int norewrite;
    int skip;

    /* unseen, previous state of mailbox (initially from .fetchids) */
    struct idlist *oldsaved, *newsaved;

    /* internal use */
    int active;
    struct hostrec *next;	/* next host in chain */
    unsigned int uid;		/* UID of user to deliver to */
    char digest [DIGESTLEN];
#ifdef HAVE_GETHOSTBYNAME
    char *canonical_name;	/* DNS canonical name of server host */
#endif /* HAVE_GETHOSTBYNAME */
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
    int (*is_old)();		/* check for old message */
    int (*fetch)();		/* fetch a given message */
    int (*trail)();		/* eat trailer of a message */
    int (*delete)();		/* delete method */
    char *expunge_cmd;		/* expunge command */
    char *exit_cmd;		/* exit command */
};

#define TAGLEN	6
extern char tag[TAGLEN];

/* list of hosts assembled from run control file and command line */
extern struct hostrec cmd_opts, *hostlist;

/* controls the detail level of status/progress messages written to stderr */
extern int outlevel;    	/* see the O_.* constants above */
extern int yydebug;		/* enable parse debugging */

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern char *logfile;		/* log file for daemon mode */
extern int quitmode;		/* if --quit was set */
extern int check_only;		/* if --check was set */

/* miscellaneous global controls */
extern char *rcfile;		/* path name of rc file */
extern char *idfile;		/* path name of UID file */
extern int linelimit;		/* limit # lines retrieved per site */
extern int versioninfo;		/* emit only version info */
extern char *dfltuser;		/* invoking user */

#ifdef HAVE_PROTOTYPES

/* prototypes for globally callable functions */
#if defined(HAVE_STDARG_H)
void gen_send (int socket, char *fmt, ... );
int gen_transact (int socket, char *fmt, ... );
#else
void gen_send ();
int gen_transact ();
#endif

void *xmalloc(int);
char *xstrdup(char *);

int doPOP2 (struct hostrec *); 
int doPOP3 (struct hostrec *);
int doIMAP (struct hostrec *);

void initialize_saved_lists(struct hostrec *, char *);
void save_uid(struct idlist **, int, char *);
void free_uid_list(struct idlist **);
void save_id_pair(struct idlist **, char *, char *);
void free_idpair_list(struct idlist **);
int delete_uid(struct idlist **, int);
int uid_in_list(struct idlist **, char *);
char *uid_find(struct idlist **, int);
char *idpair_find(struct idlist **, char *);
void append_uid_list(struct idlist **, struct idlist **);
void update_uid_lists(struct hostrec *);
void write_saved_lists(struct hostrec *, char *);

struct hostrec *hostalloc(struct hostrec *); 
int parsecmdline (int, char **, struct hostrec *);
void optmerge(struct hostrec *, struct hostrec *);
char *MD5Digest (char *);
int openmailpipe (struct hostrec *);
int daemonize(const char *, void (*)(int));

void escapes(const char *, char *);

#else

struct hostrec *hostinit(); 
char *MD5Digest ();
void optmerge();

#endif

void alarm_handler();

#define FALSE	0
#define TRUE	1
