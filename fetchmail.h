/*
 * For license terms, see the file COPYING in this directory.
 */

/* constants designating the various supported protocols */
#define		P_AUTO		0
#define		P_POP2		2
#define		P_POP3		3
#define		P_IMAP		4
#define		P_APOP		5
#define		P_RPOP		6

#define		KPOP_PORT	1109

/* authentication types */
#define		A_PASSWORD	0	/* passwords in cleartext */
#define		A_KERBEROS	1	/* get Kerberos V4 ticket */

/* definitions for buffer sizes -- somewhat arbitrary */
#define		POPBUFSIZE	512	/* per RFC 937 */
#define		MSGBUFSIZE	2048   	/* size of message read buffer */
#define		HOSTLEN		128	/* max hostname length */
#define		USERNAMELEN	32	/* max user-name length */
#define		PASSWORDLEN	64	/* max password length */
#define		DIGESTLEN	33	/* length of MD5 digest */
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
#define		PS_TRANSIENT	11	/* transient failure (internal use) */

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


struct hostdata		/* shared among all user connections to given server */
{
    /* rc file data */
    struct idlist *names;		/* server name first, then akas */
    struct idlist *localdomains;	/* list of pass-through domains */
    int protocol;
    int port;
    int authenticate;
    int timeout;
    char *envelope;
    int skip;
    int no_dns;

#ifdef linux
    char *interface;
    char *monitor;
    int  monitor_io;
    struct interface_pair_s *interface_pair;
#endif /* linux */

    /* computed for internal use */
#ifdef HAVE_GETHOSTBYNAME
    char *canonical_name;		/* DNS canonical name of server host */
#endif /* HAVE_GETHOSTBYNAME */
    struct hostdata *lead_server;	/* ptr to lead query for this server */
    int esmtp_options;
};

struct query
{
    /* mailserver connection controls */
    struct hostdata server;

    /* per-user data */
    struct idlist *localnames;		/* including calling user's name */
    int wildcard;		/* should unmatched names be passed through */
    char *remotename;
    char *password;
    char *mailbox;
    char *smtphost;
    char *mda;
    char *preconnect;

    /* per-user control flags */
    int keep;
    int fetchall;
    int flush;
    int no_rewrite;
    int limit;
    int fetchlimit;
    int batchlimit;

    /* unseen, previous state of mailbox (initially from .fetchids) */
    struct idlist *oldsaved, *newsaved;

    /* internal use */
    int active;
    int errcount;		/* count transient errors in last pass */
    struct query *next;		/* next query control block in chain */
    struct query *lead_smtp;	/* pointer to this query's SMTP leader */
    FILE *smtp_sockfp;		/* socket descriptor for SMTP connection */
    unsigned int uid;		/* UID of user to deliver to */
    char digest [DIGESTLEN];	/* md5 digest buffer */
};

#define MULTIDROP(ctl)	(ctl->wildcard || \
				((ctl)->localnames && (ctl)->localnames->next))

struct method
{
    char *name;			/* protocol name */
    int	port;			/* service port */
    int tagged;			/* if true, generate & expect command tags */
    int delimited;		/* if true, accept "." message delimiter */
    int (*parse_response)();	/* response_parsing function */
    int (*getauth)();		/* authorization fetcher */
    int (*getrange)();		/* get message range to fetch */
    int (*getsizes)();		/* get sizes of messages */
    int (*is_old)();		/* check for old message */
    int (*fetch)();		/* fetch a given message */
    int (*trail)();		/* eat trailer of a message */
    int (*delete)();		/* delete method */
    char *exit_cmd;		/* exit command */
};

#define TAGLEN	6
extern char tag[TAGLEN];

/* list of hosts assembled from run control file and command line */
extern struct query cmd_opts, *querylist;

/* controls the detail level of status/progress messages written to stderr */
extern int outlevel;    	/* see the O_.* constants above */
extern int yydebug;		/* enable parse debugging */

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern int nodetach;		/* if TRUE, don't detach daemon process */
extern char *logfile;		/* log file for daemon mode */
extern int use_syslog;		/* if --syslog was set */
extern int quitmode;		/* if --quit was set */
extern int check_only;		/* if --check was set */
extern char *cmd_logfile;	/* if --logfile was set */

/* these get computed */
extern int batchcount;		/* count of messages sent in current batch */
extern int peek_capable;	/* can we read msgs without setting seen? */

/* miscellaneous global controls */
extern char *rcfile;		/* path name of rc file */
extern char *idfile;		/* path name of UID file */
extern int linelimit;		/* limit # lines retrieved per site */
extern int versioninfo;		/* emit only version info */
extern char *user;		/* name of invoking user */

/* prototypes for globally callable functions */
#if defined(HAVE_STDARG_H)
void error_init(int foreground);
void error (int status, int errnum, const char *format, ...);
void error_build (const char *format, ...);
void error_complete (int status, int errnum, const char *format, ...);
void gen_send (FILE *sockfp, char *, ... );
int gen_recv(FILE *sockfp, char *buf, int size);
int gen_transact (FILE *sockfp, char *, ... );
#else
void error ();
void error_build ();
void error_complete ();
void gen_send ();
int gen_transact ();
#endif

void *xmalloc(int);
void *xrealloc(void *, int);
char *xstrdup(const char *);

int do_protocol(struct query *, const struct method *);
int doPOP2 (struct query *); 
int doPOP3 (struct query *);
int doIMAP (struct query *);

void reply_hack(char *, const char *);
char *nxtaddr(const char *);

void initialize_saved_lists(struct query *, const char *);
struct idlist *save_str(struct idlist **, int, const char *);
void free_str_list(struct idlist **);
void save_str_pair(struct idlist **, const char *, const char *);
void free_str_pair_list(struct idlist **);
int delete_str(struct idlist **, int);
int str_in_list(struct idlist **, const char *);
char *str_find(struct idlist **, int);
char *idpair_find(struct idlist **, const char *);
void append_str_list(struct idlist **, struct idlist **);
void update_str_lists(struct query *);
void write_saved_lists(struct query *, const char *);

struct query *hostalloc(struct query *); 
int parsecmdline (int, char **, struct query *);
void optmerge(struct query *, struct query *);
char *MD5Digest (char *);
int daemonize(const char *, void (*)(int));

int prc_parse_file(const char *);
int prc_filecheck(const char *);

void interface_parse(struct hostdata *);
void interface_note_activity(struct hostdata *);
int interface_approve(struct hostdata *);

char *getpassword(char *);

void escapes(const char *, char *);

void yyerror(const char *);
int yylex(void);

#define FALSE	0
#define TRUE	1
