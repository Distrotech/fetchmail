/*
 * For license terms, see the file COPYING in this directory.
 */

/* constants designating the various supported protocols */
#define		P_AUTO		0
#define		P_POP2		2
#define		P_POP3		3
#define		P_IMAP		4
#define		P_IMAP_K4	5
#define		P_APOP		6
#define		P_RPOP		7
#define		P_ETRN		8

#define		KPOP_PORT	1109

/* preauthentication types */
#define		A_PASSWORD	0	/* password or inline authentication */
#define		A_KERBEROS_V4	1	/* preauthenticate w/ Kerberos V4 */

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
#define		PS_EXCLUDE	8	/* client-side exclusion error */
#define		PS_LOCKBUSY	9	/* server responded lock busy */
#define		PS_SMTP         10      /* SMTP error */
#define		PS_UNDEFINED	11	/* something I hadn't thought of */
#define		PS_TRANSIENT	12	/* transient failure (internal use) */
#define		PS_REFUSED	13	/* mail refused (internal use) */

/* output noise level */
#define         O_SILENT	0	/* mute, max squelch, etc. */
#define		O_NORMAL	1	/* user-friendly */
#define		O_VERBOSE	2	/* excessive */

#define		SIZETICKER	1024	/* print 1 dot per this many bytes */

/* we need to use zero as a flag-uninitialized value */
#define FLAG_TRUE	2
#define FLAG_FALSE	1

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

/*
 * We #ifdef this and use flag rather than bool
 * to avoid a type clash with curses.h
 */
#ifndef TRUE
#define FALSE	0
#define TRUE	1
#endif /* TRUE */
typedef	char	flag;

struct hostdata		/* shared among all user connections to given server */
{
    /* rc file data */
    char *via;				/* "true" server name if non-NULL */
    struct idlist *names;		/* server name first, then akas */
    struct idlist *localdomains;	/* list of pass-through domains */
    int protocol;			/* protocol type */
    int port;				/* TCP/IP service port number */
    int interval;			/* # cycles to skip between polls */
    int preauthenticate;		/* preauthentication mode to try */
    int timeout;			/* inactivity timout in seconds */
    char *envelope;			/* envelope address list header */
    flag skip;				/* suppress poll in implicit mode? */
    flag dns;				/* do DNS lookup on multidrop? */
    flag uidl;				/* use RFC1725 UIDLs? */

#ifdef linux
    char *interface;
    char *monitor;
    int  monitor_io;
    struct interface_pair_s *interface_pair;
#endif /* linux */

    /* computed for internal use */
    int poll_count;			/* count of polls so far */
    char *truename;			/* "true name" of server host */
    struct hostdata *lead_server;	/* ptr to lead query for this server */
    int esmtp_options;
};

struct query
{
    /* mailserver connection controls */
    struct hostdata server;

    /* per-user data */
    struct idlist *localnames;	/* including calling user's name */
    int wildcard;		/* should unmatched names be passed through */
    char *remotename;		/* remote login name to use */
    char *password;		/* remote password to use */
    struct idlist *mailboxes;	/* list of mailboxes to check */
    struct idlist *smtphunt;	/* list of SMTP hosts to try forwarding to */
    char *smtphost;		/* actual SMTP host to point to */
    char *mda;			/* local MDA to pass mail to */
    char *preconnect;		/* pre-connection command to execute */

    /* per-user control flags */
    flag keep;			/* if TRUE, leave messages undeleted */
    flag fetchall;		/* if TRUE, fetch all (not just unseen) */
    flag flush;			/* if TRUE, delete messages already seen */
    flag rewrite;		/* if TRUE, canonicalize recipient addresses */
    flag stripcr;		/* if TRUE, strip CRs in text */
    flag forcecr;		/* if TRUE, force CRs before LFs in text */
    flag pass8bits;		/* if TRUE, ignore Content-Transfer-Encoding */
    flag dropstatus;		/* if TRUE, drop Status lines in mail */
    int	limit;			/* limit size of retrieved messages */
    int	fetchlimit;		/* max # msgs to get in single poll */
    int	batchlimit;		/* max # msgs to pass in single SMTP session */

    /* unseen, previous state of mailbox (initially from .fetchids) */
    struct idlist *oldsaved, *newsaved;

    /* internal use */
    flag active;		/* should we actually poll this server? */
    int errcount;		/* count transient errors in last pass */
    int smtp_socket;		/* socket descriptor for SMTP connection */
    unsigned int uid;		/* UID of user to deliver to */
    char digest [DIGESTLEN];	/* md5 digest buffer */
    struct query *next;		/* next query control block in chain */
};

#define MULTIDROP(ctl)	(ctl->wildcard || \
				((ctl)->localnames && (ctl)->localnames->next))

struct method
{
    char *name;			/* protocol name */
    int	port;			/* service port */
    flag tagged;		/* if true, generate & expect command tags */
    flag delimited;		/* if true, accept "." message delimiter */
    flag force_getsizes;	/* if true, fetch's size return unreliable */
    int (*parse_response)();	/* response_parsing function */
    int (*getauth)();		/* authorization fetcher */
    int (*getrange)();		/* get message range to fetch */
    int (*getsizes)();		/* get sizes of messages */
    int (*is_old)();		/* check for old message */
    int (*fetch_headers)();	/* fetch FROM headera given message */
    int (*fetch_body)();	/* fetch a given message */
    int (*trail)();		/* eat trailer of a message */
    int (*delete)();		/* delete method */
    char *exit_cmd;		/* exit command */
};

#define TAGLEN	6
extern char tag[TAGLEN];

/* list of hosts assembled from run control file and command line */
extern struct query cmd_opts, *querylist;

/* what's returned by envquery */
extern void envquery(int, char **);
char *user, *home, *fetchmailhost;

/* controls the detail level of status/progress messages written to stderr */
extern int outlevel;    	/* see the O_.* constants above */
extern int yydebug;		/* enable parse debugging */

/* daemon mode control */
extern int poll_interval;	/* poll interval in seconds */
extern flag nodetach;		/* if TRUE, don't detach daemon process */
extern char *logfile;		/* log file for daemon mode */
extern flag use_syslog;		/* if --syslog was set */
extern flag quitmode;		/* if --quit was set */
extern flag check_only;		/* if --check was set */
extern char *cmd_logfile;	/* if --logfile was set */
extern int cmd_daemon;		/* if --daemon was set */

/* these get computed */
extern int batchcount;		/* count of messages sent in current batch */
extern flag peek_capable;	/* can we read msgs without setting seen? */

/* miscellaneous global controls */
extern char *rcfile;		/* path name of rc file */
extern char *idfile;		/* path name of UID file */
extern int linelimit;		/* limit # lines retrieved per site */
extern flag versioninfo;	/* emit only version info */
extern char *user;		/* name of invoking user */
extern char *fetchmailhost;	/* the name of the host running fetchmail */

/* prototypes for globally callable functions */
#if defined(HAVE_STDARG_H)
void error_init(int foreground);
void error (int status, int errnum, const char *format, ...);
void error_build (const char *format, ...);
void error_complete (int status, int errnum, const char *format, ...);
void error_at_line (int, int, const char *, unsigned int, const char *, ...);
void gen_send (int sock, char *, ... );
int gen_recv(int sock, char *buf, int size);
int gen_transact (int sock, char *, ... );
#else
void error ();
void error_build ();
void error_complete ();
void error_at_line ();
void gen_send ();
int gen_transact ();
#endif

int do_protocol(struct query *, const struct method *);
int doPOP2 (struct query *); 
int doPOP3 (struct query *);
int doIMAP (struct query *);
int doETRN (struct query *);

void reply_hack(char *, const char *);
char *nxtaddr(const char *);

/* UID support */
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

int prc_parse_file(const char *, flag);
int prc_filecheck(const char *);

void interface_parse(char *, struct hostdata *);
void interface_note_activity(struct hostdata *);
int interface_approve(struct hostdata *);

char *getpassword(char *);

void escapes(const char *, char *);
char *visbuf(const char *);
char *showproto(int);

void yyerror(const char *);
int yylex(void);

void to64frombits(unsigned char *, const unsigned char *, int);
int from64tobits(char *, const char *);

#if defined(HAVE_VOIDPOINTER)
#define XMALLOCTYPE void
#else
#define XMALLOCTYPE char
#endif

XMALLOCTYPE *xmalloc(int);
XMALLOCTYPE *xrealloc(XMALLOCTYPE *, int);
char *xstrdup(const char *);

#define STRING_DISABLED	(char *)-1

/* fetchmail.h ends here */
