/*
 * fetchmail.c -- main driver module for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if defined(HAVE_ALLOCA_H)
#include <alloca.h>
#endif
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef NeXT
#  define pid_t int
#endif

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#endif /* HAVE_GETHOSTBYNAME */

#include "fetchmail.h"
#include "tunable.h"
#include "smtp.h"
#include "getopt.h"

#define DROPDEAD	6	/* maximum bad socket opens */

/* prototypes for internal functions */
static int load_params(int, char **, int);
static void dump_params (struct query *);
static int query_host(struct query *);
static char *visbuf(const char *);

/* controls the detail level of status/progress messages written to stderr */
int outlevel;    	/* see the O_.* constants above */
int yydebug;		/* enable parse debugging */

/* daemon mode control */
int poll_interval;	/* poll interval in seconds */
int nodetach;		/* if TRUE, don't detach daemon process */
char *logfile;		/* log file for daemon mode */
int quitmode;		/* if --quit was set */
int check_only;		/* if --probe was set */
int cmd_batchlimit;	/* if --batchlimit was set */
int cmd_fetchlimit;	/* if --fetchlimit was set */
char *cmd_logfile;	/* if --logfile was set */
char *interface;	/* interface required specification */
char *cmd_interface;	/* if --interface was set */
char *monitor;		/* monitored interface for activity */
char *cmd_monitor;	/* if --monitor was set */

/* miscellaneous global controls */
char *rcfile;		/* path name of rc file */
char *idfile;		/* UID list file */
int versioninfo;	/* emit only version info */
char *user;		/* the name of the invoking user */
char *program_name;	/* the name to prefix error messages with */

static char *lockfile;		/* name of lockfile */
static int querystatus;		/* status of query */
static int lastsig;		/* last signal received */

static void termhook();		/* forward declaration of exit hook */

RETSIGTYPE donothing(sig) int sig; {signal(sig, donothing); lastsig = sig;}

static void unlockit(void)
/* must-do actions for exit (but we can't count on being able to do malloc) */
{
    unlink(lockfile);
}

int main (int argc, char **argv)
{
    int st, bkgd = FALSE;
    int parsestatus, implicitmode;
    char *home, *tmpdir, tmpbuf[BUFSIZ]; 
    struct passwd *pw;
    struct query *ctl;
    FILE	*lockfp;
    pid_t pid;

    if ((program_name = strrchr(argv[0], '/')) != NULL)
	++program_name;
    else
	program_name = argv[0];

    if ((user = getenv("USER")) == (char *)NULL)
        user = getenv("LOGNAME");

    if ((user == (char *)NULL) || (home = getenv("HOME")) == (char *)NULL)
    {
	if ((pw = getpwuid(getuid())) != NULL)
	{
	    user = pw->pw_name;
	    home = pw->pw_dir;
	}
	else
	{
	    fprintf(stderr,"fetchmail: can't find your name and home directory!\n");
	    exit(PS_UNDEFINED);
	}
    }

    /*
     * Backward-compatibility hack.  If we're called by the name of the
     * ancestral popclient, look for .poprc.  This will actually work 
     * for popclient files that don't use the removed keywords.
     */
    if (strcmp("popclient", argv[0]) == 0)
	tmpdir = ".poprc";
    else
	tmpdir = ".fetchmailrc";

    rcfile = (char *) xmalloc(strlen(home)+strlen(tmpdir)+2);
    strcpy(rcfile, home);
    strcat(rcfile, "/");
    strcat(rcfile, tmpdir);

#define IDFILE_NAME	".fetchids"
    idfile = (char *) xmalloc(strlen(home)+strlen(IDFILE_NAME)+2);
    strcpy(idfile, home);
    strcat(idfile, "/");
    strcat(idfile, IDFILE_NAME);
  
    outlevel = O_NORMAL;

    if ((parsestatus = parsecmdline(argc,argv,&cmd_opts)) < 0)
	exit(PS_SYNTAX);

    /* this hint to stdio should halp messages come out in the right order */
    setvbuf(stdout, NULL, _IOLBF, POPBUFSIZE);

    if (versioninfo)
	printf("This is fetchmail release %s pl %s\n", RELEASE_ID, PATCHLEVEL);

    /* avoid parsing the config file if all we're doing is killing a daemon */ 
    if (!quitmode)
	implicitmode = load_params(argc, argv, optind);

    /* set up to do lock protocol */
    if ((tmpdir = getenv("TMPDIR")) == (char *)NULL)
	tmpdir = "/tmp";
    strcpy(tmpbuf, tmpdir);
    strcat(tmpbuf, "/fetchmail-");
    strcat(tmpbuf, user);

    /* perhaps we just want to check options? */
    if (versioninfo) {
	printf("Taking options from command line");
	if (access(rcfile, 0))
	    printf("\n");
	else
	    printf(" and %s\n", rcfile);
	if (outlevel == O_VERBOSE)
	    printf("Lockfile at %s\n", tmpbuf);
	if (batchlimit)
	    printf("SMTP message batch limit is %d.\n", batchlimit);
	else
	    printf("No SMTP message batch limit.\n");
	for (ctl = querylist; ctl; ctl = ctl->next) {
	    if (ctl->active && !(implicitmode && ctl->skip))
		dump_params(ctl);
	}
	if (querylist == NULL)
	    (void) fprintf(stderr,
		"No mailservers set up -- perhaps %s is missing?\n",
			  rcfile);
	exit(0);
    }
    else if (!quitmode && querylist == NULL) {
	(void) fputs("fetchmail: no mailservers have been specified.\n", stderr);
	exit(PS_SYNTAX);
    }

    /* check for another fetchmail running concurrently */
    pid = -1;
    if ((lockfile = (char *) malloc(strlen(tmpbuf) + 1)) == NULL)
    {
	fprintf(stderr,"fetchmail: cannot allocate memory for lock name.\n");
	exit(PS_EXCLUDE);
    }
    else
	(void) strcpy(lockfile, tmpbuf);
    if ((lockfp = fopen(lockfile, "r")) != NULL )
    {
	bkgd = (fscanf(lockfp,"%d %d", &pid, &st) == 2);

	if (kill(pid, 0) == -1) {
	    fprintf(stderr,"fetchmail: removing stale lockfile\n");
	    pid = -1;
	    bkgd = FALSE;
	    remove(lockfile);
	}
	fclose(lockfp);
    }

    /* perhaps user asked us to kill the other fetchmail */
    if (quitmode)
    {
	if (pid == -1) 
	{
	    fprintf(stderr,"fetchmail: no other fetchmail is running\n");
	    exit(PS_EXCLUDE);
	}
	else if (kill(pid, SIGTERM) < 0)
	{
	    fprintf(stderr,"fetchmail: error killing %s fetchmail at %d.\n",
		    bkgd ? "background" : "foreground", pid);
	    exit(PS_EXCLUDE);
	}
	else
	{
	    fprintf(stderr,"fetchmail: %s fetchmail at %d killed.\n",
		    bkgd ? "background" : "foreground", pid);
	    remove(lockfile);
	    exit(0);
	}
    }

    /* another fetchmail is running -- wake it up or die */
    if (pid != -1)
    {
	if (check_only)
	{
	    fprintf(stderr,
		 "fetchmail: can't check mail while another fetchmail to same host is running.");
	    return(PS_EXCLUDE);
        }
	else if (!implicitmode)
	{
	    fprintf(stderr,
		 "fetchmail: can't poll specified hosts with another fetchmail running at %d.\n",
		 pid);
		return(PS_EXCLUDE);
	}
	else if (!bkgd)
	{
	    fprintf(stderr,
		 "fetchmail: another foreground fetchmail is running at %d.\n",
		 pid);
		return(PS_EXCLUDE);
	}
	else if (kill(pid, SIGUSR1) == 0)
	{
	    fprintf(stderr,
		    "fetchmail: background fetchmail at %d awakened.\n",
		    pid);
	    return(0);
	}
	else
	{
	    /*
	     * Should never happen -- possible only if a background fetchmail
	     * croaks after the first kill probe above but before the SIGUSR1
	     * transmission.
	     */
	    fprintf(stderr,
		    "fetchmail: elder sibling at %d died mysteriously.\n",
		    pid);
	    return(PS_UNDEFINED);
	}
    }

    /* pick up interactively any passwords we need but don't have */ 
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl->active && !(implicitmode && ctl->skip) && !ctl->password[0])
	{
	    if (ctl->authenticate == A_KERBEROS)
	      /* Server won't care what the password is, but there
		 must be some non-null string here.  */
	      (void) strncpy(ctl->password, 
			     ctl->remotename, PASSWORDLEN-1);
	    else
	      {
		(void) sprintf(tmpbuf, "Enter password for %s@%s: ",
			       ctl->remotename, ctl->servernames->id);
		(void) strncpy(ctl->password,
			       (char *)getpassword(tmpbuf),PASSWORDLEN-1);
	      }
	}

    /*
     * Maybe time to go to demon mode...
     */
    if (poll_interval && !nodetach)
	daemonize(logfile, termhook);

    /* beyond here we don't want more than one fetchmail running per user */
    umask(0077);
    signal(SIGABRT, termhook);
    signal(SIGINT, termhook);
    signal(SIGTERM, termhook);
    signal(SIGALRM, termhook);
    signal(SIGPIPE, termhook);
    signal(SIGQUIT, termhook);

    /*
     * With this simple hack, we make it possible for a foreground 
     * fetchmail to wake up one in daemon mode.  What we want is the
     * side effect of interrupting any sleep that may be going on,
     * forcing fetchmail to re-poll its hosts.
     */
    signal(SIGUSR1, donothing);

    /* here's the exclusion lock */
    if ( (lockfp = fopen(lockfile,"w")) != NULL ) {
	fprintf(lockfp,"%d",getpid());
	if (poll_interval)
	    fprintf(lockfp," %d", poll_interval);
	fclose(lockfp);
	atexit(unlockit);
    }

    /*
     * Query all hosts. If there's only one, the error return will
     * reflect the status of that transaction.
     */
    do {
#ifdef HAVE_RES_SEARCH
	sethostent(TRUE);	/* use TCP/IP for mailserver queries */
#endif /* HAVE_RES_SEARCH */

	batchcount = 0;
	for (ctl = querylist; ctl; ctl = ctl->next)
	{
	    if (ctl->active && !(implicitmode && ctl->skip))
	    {
#ifdef HAVE_GETHOSTBYNAME
		/*
		 * This functions partly as an optimization and partly
		 * as a probe to make sure our nameserver is still up.
		 * The multidrop case (especially) needs it.
		 */
		if (ctl->authenticate == A_KERBEROS || MULTIDROP(ctl))
		{
		    struct hostent	*namerec;

		    /* compute the canonical name of the host */
		    errno = 0;
		    namerec = gethostbyname(ctl->servernames->id);
		    if (namerec == (struct hostent *)NULL)
		    {
			error(0, errno,
				"skipping %s poll, ",
				ctl->servernames->id);
			if (errno)
			{
			    if (errno == ENETUNREACH)
				break;	/* go to sleep */
			}
#ifdef HAVE_HERROR		/* NEXTSTEP doesn't */
			else
			    herror("DNS error");
#endif /* HAVE_HERROR */
			continue;
		    }
		    else
		    {
			free(ctl->canonical_name);
			ctl->canonical_name = xstrdup((char *)namerec->h_name);
		    }
		}
#endif /* HAVE_GETHOSTBYNAME */

		querystatus = query_host(ctl);
		if (!check_only)
		    update_str_lists(ctl);
	    }
	}

#ifdef HAVE_RES_SEARCH
	endhostent();		/* release TCP/IP connection to nameserver */
#endif /* HAVE_RES_SEARCH */

	/*
	 * Close all SMTP delivery sockets.  For optimum performance
	 * we'd like to hold them open til end of run, but (1) this
	 * loses if our poll interval is longer than the MTA's inactivity
	 * timeout, and (2) some MTAs (like smail) don't deliver after
	 * each message, but rather queue up mail and wait to actually
	 * deliver it until the input socket is closed. 
	 */
	for (ctl = querylist; ctl; ctl = ctl->next)
	    if (ctl->smtp_sockfp)
	    {
		SMTP_quit(ctl->smtp_sockfp);
		fclose(ctl->smtp_sockfp);
		ctl->smtp_sockfp = (FILE *)NULL;
	    }

	if (poll_interval)
	{
	    if (outlevel == O_VERBOSE)
	    {
		time_t	now;

		time(&now);
		fprintf(stderr, "fetchmail: sleeping at %s", ctime(&now));
	    }

	    /*
	     * We can't use sleep(3) here because we need an alarm(3)
	     * equivalent in order to implement server nonresponse timeout.
	     * We'll just assume setitimer(2) is available since fetchmail
	     * has to have a BSDoid socket layer to work at all.
	     */
#ifdef	linux
	    do {
		interface_note_activity();
#endif
	    {
		struct itimerval ntimeout;

		ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
		ntimeout.it_value.tv_sec  = poll_interval;
		ntimeout.it_value.tv_usec = 0;

		setitimer(ITIMER_REAL,&ntimeout,NULL);
		signal(SIGALRM, donothing);
		pause();
		if (lastsig == SIGUSR1)
		    (void) error(0, 0, "awakened by SIGUSR1");
	    }
#ifdef	linux
	    } while (!interface_approve());
#endif

	    if (outlevel == O_VERBOSE)
	    {
		time_t	now;

		time(&now);
		fprintf(stderr, "fetchmail: awakened at %s", ctime(&now));
	    }
	}
    } while
	(poll_interval);

    if (outlevel == O_VERBOSE)
	fprintf(stderr,"fetchmail: normal termination, status %d\n",querystatus);

    termhook(0);
    exit(querystatus);
}

static int load_params(int argc, char **argv, int optind)
{
    int	implicitmode, st;
    struct passwd *pw;
    struct query def_opts, *ctl, *mp;

    memset(&def_opts, '\0', sizeof(struct query));

    def_opts.protocol = P_AUTO;
    def_opts.timeout = CLIENT_TIMEOUT;
    strcpy(def_opts.remotename, user);
    strcpy(def_opts.smtphost, "localhost");

    /* this builds the host list */
    if (prc_parse_file(rcfile) != 0)
	exit(PS_SYNTAX);

    if ((implicitmode = (optind >= argc)))
    {
	for (ctl = querylist; ctl; ctl = ctl->next)
	    ctl->active = TRUE;
    }
    else
	for (; optind < argc; optind++) 
	{
	    /*
	     * If hostname corresponds to a host known from the rc file,
	     * simply declare it active.  Otherwise synthesize a host
	     * record from command line and defaults
	     */
	    for (ctl = querylist; ctl; ctl = ctl->next)
		if (str_in_list(&ctl->servernames, argv[optind]))
		    goto foundit;

	    ctl = hostalloc(&cmd_opts);
	    save_str(&ctl->servernames, -1, argv[optind]);

	foundit:
	    ctl->active = TRUE;
	}

    /* if there's a defaults record, merge it and lose it */ 
    if (querylist && strcmp(querylist->servernames->id, "defaults") == 0)
    {
	for (ctl = querylist; ctl; ctl = ctl->next)
	    optmerge(ctl, querylist);
	querylist = querylist->next;
    }

    /* don't allow a defaults record after the first */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl != querylist && strcmp(ctl->servernames->id, "defaults") == 0)
	    exit(PS_SYNTAX);

    /* merge in wired defaults, do sanity checks and prepare internal fields */
    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	if (ctl->active && !(implicitmode && ctl->skip))
	{
	    /* merge in defaults */
	    optmerge(ctl, &def_opts);

	    /* keep lusers from shooting themselves in the foot :-) */
	    if (poll_interval && ctl->limit)
	    {
		fprintf(stderr,"fetchmail: you'd never see large messages!\n");
		exit(PS_SYNTAX);
	    }

	    /* make sure delivery will default to a real local user */
	    if ((pw = getpwnam(user)) == (struct passwd *)NULL)
	    {
		fprintf(stderr,
			"fetchmail: can't set up default delivery to %s\n", user);
		exit(PS_SYNTAX);	/* has to be from bad rc file */
	    }
	    else
	    {
		ctl->uid = pw->pw_uid;	/* for local delivery via MDA */
		if (!ctl->localnames)	/* for local delivery via SMTP */
		    save_str(&ctl->localnames, -1, user);
	    }

#if !defined(HAVE_GETHOSTBYNAME) || !defined(HAVE_RES_SEARCH)
	    /* can't handle multidrop mailboxes unless we can do DNS lookups */
	    if (ctl->localnames && ctl->localnames->next)
	    {
		fputs("fetchmail: can't handle multidrop mailboxes without DNS\n",
			stderr);
		exit(PS_SYNTAX);
	    }
#endif /* !HAVE_GETHOSTBYNAME || !HAVE_RES_SEARCH */

	    /*
	     * Assign SMTP leaders.  We want to allow all query blocks
	     * sharing the same SMTP host to use the same SMTP connection.
	     * To accomplish this, we initialize each query block's leader
	     * field to point to the first block in the list with a matching 
	     * SMTP host.
	     *
	     * In the typical case, there will be only one SMTP host (the
	     * client machine) and thus just one SMTP leader (and one listener
	     * process) through the entire poll cycle.
	     */
	    if (!ctl->mda[0])
	    {
		ctl->smtp_sockfp = (FILE *)NULL;
		for (mp = querylist; mp && mp != ctl; mp = mp->next)
		    if (strcmp(mp->smtphost, ctl->smtphost) == 0)
		    {
			ctl->lead_smtp = mp->lead_smtp;
			goto no_new_leader;
		    }
		ctl->lead_smtp = ctl;
	    no_new_leader:;
	    }

	    /* similarly, compute server leaders for queries */
	    for (mp = querylist; mp && mp != ctl; mp = mp->next)
		if (strcmp(mp->servernames->id, ctl->servernames->id) == 0)
		{
		    ctl->lead_server = mp->lead_server;
		    goto no_new_server;
		}
	    ctl->lead_server = ctl;
	no_new_server:;

	    /* plug in the semi-standard way of indicating a mail address */
	    if (ctl->envelope == (char *)NULL)
		ctl->envelope = "X-Envelope-To:";

	    /* sanity checks */
	    if (ctl->port < 0)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, port number cannot be negative",
			       ctl->servernames->id);
		exit(PS_SYNTAX);
	    }
	}
    }

    /* initialize UID handling */
    if ((st = prc_filecheck(idfile)) != 0)
	exit(st);
    else
	initialize_saved_lists(querylist, idfile);

    /* if cmd_batchlimit was explicitly set, use it to override batchlimit */
   if (cmd_batchlimit > -1)
	batchlimit = cmd_batchlimit;

    /* if cmd_logfile was explicitly set, use it to override logfile */
    if (cmd_logfile)
	logfile = cmd_logfile;

    /* if cmd_interface was explicitly set, use it to override interface */
    if (cmd_interface)
	interface = cmd_interface;

    /* if cmd_monitor was explicitly set, use it to override monitor */
    if (cmd_monitor)
	monitor = cmd_monitor;

    if (interface)
#ifdef	linux
	interface_parse();
#else
	{
	    (void) fprintf(stderr,
	    		"interface specification supported only on Linux\n");
	    exit(PS_SYNTAX);
	}
    if (monitor)
	{
	    (void) fprintf(stderr,
	    		"monitor supported only on Linux\n");
	    exit(PS_SYNTAX);
	}
#endif

    return(implicitmode);
}

void termhook(int sig)
/* to be executed on normal or signal-induced termination */
{
    struct query	*ctl;

    /*
     * Sending SMTP QUIT on signal is theoretically nice, but led to a 
     * subtle bug.  If fetchmail was terminated by signal while it was 
     * shipping message text, it would hang forever waiting for a
     * command acknowledge.  In theory we could disable the QUIT
     * only outside of the message send.  In practice, we don't
     * care.  All mailservers hang up on a dropped TCP/IP connection
     * anyway.
     */

    if (sig != 0)
        error(0, 0, "terminated with signal %d", sig);
    else
	/* terminate all SMTP connections cleanly */
	for (ctl = querylist; ctl; ctl = ctl->next)
	    if (ctl->lead_smtp == ctl && ctl->smtp_sockfp != (FILE *)NULL)
		SMTP_quit(ctl->smtp_sockfp);

    if (!check_only)
	write_saved_lists(querylist, idfile);

    exit(querystatus);
}

static char *showproto(int proto)
/* protocol index to protocol name mapping */
{
    switch (proto)
    {
    case P_AUTO: return("auto"); break;
    case P_POP2: return("POP2"); break;
    case P_POP3: return("POP3"); break;
    case P_IMAP: return("IMAP"); break;
    case P_APOP: return("APOP"); break;
    default: return("unknown?!?"); break;
    }
}

/*
 * Sequence of protocols to try when autoprobing, most capable to least.
 */
static const int autoprobe[] = {P_IMAP, P_POP3, P_POP2};

static int query_host(struct query *ctl)
/* perform fetch transaction with single host */
{
    int i, st;

    if (outlevel == O_VERBOSE)
    {
	time_t now;

	time(&now);
	fprintf(stderr, "Querying %s (protocol %s) at %s",
	    ctl->servernames->id, showproto(ctl->protocol), ctime(&now));
    }
    switch (ctl->protocol) {
    case P_AUTO:
	for (i = 0; i < sizeof(autoprobe)/sizeof(autoprobe[0]); i++)
	{
	    ctl->protocol = autoprobe[i];
	    if ((st = query_host(ctl)) == PS_SUCCESS || st == PS_NOMAIL || st == PS_AUTHFAIL)
		break;
	}
	ctl->protocol = P_AUTO;
	return(st);
	break;
    case P_POP2:
	return(doPOP2(ctl));
	break;
    case P_POP3:
    case P_APOP:
	return(doPOP3(ctl));
	break;
    case P_IMAP:
	return(doIMAP(ctl));
	break;
    default:
	error(0, 0, "unsupported protocol selected.");
	return(PS_PROTOCOL);
    }
}

void dump_params (struct query *ctl)
/* display query parameters in English */
{
    printf("Options for retrieving from %s@%s:\n",
	   ctl->remotename, visbuf(ctl->servernames->id));
#ifdef HAVE_GETHOSTBYNAME
    if (ctl->canonical_name)
	printf("  Canonical DNS name of server is %s.\n", ctl->canonical_name);
#endif /* HAVE_GETHOSTBYNAME */
    if (ctl->servernames->next)
    {
	struct idlist *idp;

	printf("  Predeclared mailserver aliases:");
	for (idp = ctl->servernames->next; idp; idp = idp->next)
	    printf(" %s", idp->id);
	putchar('\n');
    }
    if (ctl->skip || outlevel == O_VERBOSE)
	printf("  This host will%s be queried when no host is specified.\n",
	       ctl->skip ? " not" : "");
    if (ctl->password[0] == '\0')
	printf("  Password will be prompted for.\n");
    else if (outlevel == O_VERBOSE)
	if (ctl->protocol == P_APOP)
	    printf("  APOP secret = '%s'.\n", visbuf(ctl->password));
        else
	    printf("  Password = '%s'.\n", visbuf(ctl->password));
    if (ctl->protocol == P_POP3 
		&& ctl->port == KPOP_PORT
		&& ctl->authenticate == A_KERBEROS)
	printf("  Protocol is KPOP");
    else
	printf("  Protocol is %s", showproto(ctl->protocol));
    if (ctl->port)
	printf(" (using port %d)", ctl->port);
    else if (outlevel == O_VERBOSE)
	printf(" (using default port)");
    putchar('.');
    putchar('\n');
    if (ctl->authenticate == A_KERBEROS)
	    printf("  Kerberos authentication enabled.\n");
    printf("  Server nonresponse timeout is %d seconds", ctl->timeout);
    if (ctl->timeout ==  CLIENT_TIMEOUT)
	printf(" (default).\n");
    else
	printf(".\n");

    printf("  %s messages will be retrieved (--all %s).\n",
	   ctl->fetchall ? "All" : "Only new",
	   ctl->fetchall ? "on" : "off");
    printf("  Fetched messages will%s be kept on the server (--keep %s).\n",
	   ctl->keep ? "" : " not",
	   ctl->keep ? "on" : "off");
    printf("  Old messages will%s be flushed before message retrieval (--flush %s).\n",
	   ctl->flush ? "" : " not",
	   ctl->flush ? "on" : "off");
    printf("  Rewrite of server-local addresses is %sabled (--norewrite %s).\n",
	   ctl->norewrite ? "dis" : "en",
	   ctl->norewrite ? "on" : "off");
    if (ctl->limit)
	printf("  Message size limit is %d bytes (--limit %d).\n", 
	       ctl->limit, ctl->limit);
    else if (outlevel == O_VERBOSE)
	printf("  No message size limit (--limit 0).\n");
    if (ctl->fetchlimit)
	printf("  Received-message limit is %d (--fetchlimit %d).\n",
	       ctl->fetchlimit, ctl->fetchlimit);
    else if (outlevel == O_VERBOSE)
	printf("  No received-message limit (--fetchlimit 0).\n");
    if (ctl->mda[0])
	printf("  Messages will be delivered with '%s.'\n", visbuf(ctl->mda));
    else
	printf("  Messages will be SMTP-forwarded to '%s'.\n", visbuf(ctl->smtphost));
    if (!ctl->localnames)
	printf("  No localnames declared for this host.\n");
    else
    {
	struct idlist *idp;
	int count = 0;

	for (idp = ctl->localnames; idp; idp = idp->next)
	    ++count;

	printf("  %d local name(s) recognized%s.\n",
	       count,
	       (count == 1 && !strcmp(ctl->localnames->id, user)) ? " (by default)" : "");
	if (outlevel == O_VERBOSE)
	{
	    for (idp = ctl->localnames; idp; idp = idp->next)
		if (idp->val.id2)
		    printf("\t%s -> %s\n", idp->id, idp->val.id2);
		else
		    printf("\t%s\n", idp->id);
	    if (ctl->wildcard)
		fputs("*\n", stdout);
	}

	if (count > 1)
	    printf("  Envelope header is assumed to be: %s\n", ctl->envelope);
    }

    if (ctl->protocol > P_POP2)
	if (!ctl->oldsaved)
	    printf("  No UIDs saved from this host.\n");
	else
	{
	    struct idlist *idp;
	    int count = 0;

	    for (idp = ctl->oldsaved; idp; idp = idp->next)
		++count;

	    printf("  %d UIDs saved.\n", count);
	    if (outlevel == O_VERBOSE)
		for (idp = ctl->oldsaved; idp; idp = idp->next)
		    fprintf(stderr, "\t%s\n", idp->id);
	}
}

/* helper functions for string interpretation and display */

#define CTRL(x)	((x) & 0x1f)

void escapes(cp, tp)
/* process standard C-style escape sequences in a string */
const char	*cp;	/* source string with escapes */
char		*tp;	/* target buffer for digested string */
{
    while (*cp)
    {
	int	cval = 0;

	if (*cp == '\\' && strchr("0123456789xX", cp[1]))
	{
	    char *dp, *hex = "00112233445566778899aAbBcCdDeEfF";
	    int dcount = 0;

	    if (*++cp == 'x' || *cp == 'X')
		for (++cp; (dp = strchr(hex, *cp)) && (dcount++ < 2); cp++)
		    cval = (cval * 16) + (dp - hex) / 2;
	    else if (*cp == '0')
		while (strchr("01234567",*cp) != (char*)NULL && (dcount++ < 3))
		    cval = (cval * 8) + (*cp++ - '0');
	    else
		while ((strchr("0123456789",*cp)!=(char*)NULL)&&(dcount++ < 3))
		    cval = (cval * 10) + (*cp++ - '0');
	}
	else if (*cp == '\\')		/* C-style character escapes */
	{
	    switch (*++cp)
	    {
	    case '\\': cval = '\\'; break;
	    case 'n': cval = '\n'; break;
	    case 't': cval = '\t'; break;
	    case 'b': cval = '\b'; break;
	    case 'r': cval = '\r'; break;
	    default: cval = *cp;
	    }
	    cp++;
	}
	else if (*cp == '^')		/* expand control-character syntax */
	{
	    cval = CTRL(*++cp);
	    cp++;
	}
	else
	    cval = *cp++;
	*tp++ = cval;
    }
    *tp = '\0';
}

static char *visbuf(const char *buf)
/* visibilize a given string */
{
    static char vbuf[BUFSIZ];
    char *tp = vbuf;

    while (*buf)
    {
	if (isprint(*buf) || *buf == ' ')
	    *tp++ = *buf++;
	else if (*buf == '\n')
	{
	    *tp++ = '\\'; *tp++ = 'n';
	    buf++;
	}
	else if (*buf == '\r')
	{
	    *tp++ = '\\'; *tp++ = 'r';
	    buf++;
	}
	else if (*buf == '\b')
	{
	    *tp++ = '\\'; *tp++ = 'b';
	    buf++;
	}
	else if (*buf < ' ')
	{
	    *tp++ = '\\'; *tp++ = '^'; *tp++ = '@' + *buf;
	    buf++;
	}
	else
	{
	    (void) sprintf(tp, "\\0x%02x", *buf++);
	    tp += strlen(tp);
	}
    }
    *tp++ = '\0';
    return(vbuf);
}

/* fetchmail.c ends here */
