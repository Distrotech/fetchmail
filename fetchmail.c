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
#if defined(HAVE_SYSLOG)
#include <syslog.h>
#endif
#include <pwd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#endif /* HAVE_GETHOSTBYNAME */

#ifdef SUNOS
#include <stdlib.h>
#endif

#include "fetchmail.h"
#include "tunable.h"
#include "smtp.h"
#include "getopt.h"
#include "netrc.h"

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
bool nodetach;		/* if TRUE, don't detach daemon process */
char *logfile;		/* log file for daemon mode */
bool use_syslog;	/* if --syslog was set */
bool quitmode;		/* if --quit was set */
bool check_only;	/* if --probe was set */
char *cmd_logfile;	/* if --logfile was set */
int cmd_daemon; 	/* if --daemon was set */

/* miscellaneous global controls */
char *rcfile;		/* path name of rc file */
char *idfile;		/* UID list file */
bool versioninfo;	/* emit only version info */
char *user;		/* the name of the invoking user */
char *fetchmailhost;	/* the name of the host running fetchmail */
char *program_name;	/* the name to prefix error messages with */

static char *lockfile;		/* name of lockfile */
static int querystatus;		/* status of query */
static int lastsig;		/* last signal received */

static void termhook();		/* forward declaration of exit hook */

RETSIGTYPE donothing(sig) int sig; {signal(sig, donothing); lastsig = sig;}

#ifdef HAVE_ATEXIT
static void unlockit(void)
#else  /* use on_exit(), e.g. on SunOS */
static void unlockit(int n, void *p)
#endif
/* must-do actions for exit (but we can't count on being able to do malloc) */
{
    unlink(lockfile);
}

int main (int argc, char **argv)
{
    int st, bkgd = FALSE;
    int parsestatus, implicitmode = FALSE;
    char *home, *tmpdir, tmpbuf[BUFSIZ]; 
    struct passwd *pw;
    struct query *ctl;
    FILE	*lockfp;
    netrc_entry *netrc_list;
    char *netrc_file;
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

    /* we'll need this for the SMTP forwarding target and error messages */
    if (gethostname(tmpbuf, sizeof(tmpbuf)))
    {
	fprintf(stderr, "fetchmail: can't determine fetchmail's host!");
	exit(PS_IOERR);
    }
    fetchmailhost = xstrdup(tmpbuf);

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

    /* this hint to stdio should help messages come out in the right order */
    setvbuf(stdout, NULL, _IOLBF, POPBUFSIZE);

    if (versioninfo)
	printf("This is fetchmail release %s\n", RELEASE_ID);

    /* avoid parsing the config file if all we're doing is killing a daemon */ 
    if (!quitmode)
	implicitmode = load_params(argc, argv, optind);

    /* set up to do lock protocol */
    if (!getuid())
	strcpy(tmpbuf, "/var/run/fetchmail.pid");
    else {
	strcpy(tmpbuf, home);
	strcat(tmpbuf, "/.fetchmail");
    }

    /* perhaps we just want to check options? */
    if (versioninfo) {
	printf("Taking options from command line");
	if (access(rcfile, 0))
	    printf("\n");
	else
	    printf(" and %s\n", rcfile);
	if (outlevel == O_VERBOSE)
	    printf("Lockfile at %s\n", tmpbuf);
	for (ctl = querylist; ctl; ctl = ctl->next) {
	    if (ctl->active && !(implicitmode && ctl->server.skip))
		dump_params(ctl);
	}
	if (querylist == NULL)
	    (void) fprintf(stderr,
		"No mailservers set up -- perhaps %s is missing?\n", rcfile);
	exit(0);
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
	    unlink(lockfile);
	}
	fclose(lockfp);
    }

    /* if no mail servers listed and nothing in background, we're done */
    if (!quitmode && pid == -1 && querylist == NULL) {
	(void)fputs("fetchmail: no mailservers have been specified.\n",stderr);
	exit(PS_SYNTAX);
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
	    unlink(lockfile);
	    exit(0);
	}
    }

    /* another fetchmail is running -- wake it up or die */
    if (pid != -1)
    {
	if (check_only)
	{
	    fprintf(stderr,
		 "fetchmail: can't check mail while another fetchmail to same host is running.\n");
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
	else if (argc > 1)
	{
	    fprintf(stderr,
		    "fetchmail: can't accept options while a background fetchmail is running.\n");
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
	     * croaks after the first kill probe above but before the
	     * SIGUSR1/SIGHUP transmission.
	     */
	    fprintf(stderr,
		    "fetchmail: elder sibling at %d died mysteriously.\n",
		    pid);
	    return(PS_UNDEFINED);
	}
    }

    /* parse the ~/.netrc file (if present) for future password lookups. */
    netrc_file = (char *) xmalloc (strlen (home) + 8);
    strcpy (netrc_file, home);
    strcat (netrc_file, "/.netrc");
    netrc_list = parse_netrc(netrc_file);

    /* pick up interactively any passwords we need but don't have */ 
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl->active && !(implicitmode && ctl->server.skip)&&!ctl->password)
	{
	    if (ctl->server.preauthenticate == A_KERBEROS_V4 || ctl->server.protocol == P_IMAP_K4)
		/* Server won't care what the password is, but there
		   must be some non-null string here.  */
		ctl->password = ctl->remotename;
	    else
	    {
		/* look up the host and account in the .netrc file. */
		netrc_entry *p = search_netrc(netrc_list,ctl->server.names->id);
		while (p && strcmp(p->account, ctl->remotename))
		    p = search_netrc(p->next, ctl->remotename);

		/* if we find a matching entry with a password, use it */
		if (p && p->password)
		    ctl->password = xstrdup(p->password);
	    }

	    if (ctl->server.protocol != P_ETRN && ctl->server.protocol != P_IMAP_K4 && !ctl->password)
	    {
		(void) sprintf(tmpbuf, "Enter password for %s@%s: ",
			       ctl->remotename, ctl->server.names->id);
		ctl->password = xstrdup((char *)getpassword(tmpbuf));
	    }
	}

    /*
     * Maybe time to go to demon mode...
     */
#if defined(HAVE_SYSLOG)
    if (use_syslog)
    	openlog(program_name, LOG_PID, LOG_MAIL);
#endif

    if (poll_interval)
    {
	if (!nodetach)
	    daemonize(logfile, termhook);
	error( 0, 0, "starting fetchmail %s daemon ", RELEASE_ID);
    }

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

    /* pacify people who think all system daemons wake up on SIGHUP */
    if (poll_interval && !getuid())
	signal(SIGHUP, donothing);

    /* here's the exclusion lock */
    if ( (lockfp = fopen(lockfile,"w")) != NULL ) {
	fprintf(lockfp,"%d",getpid());
	if (poll_interval)
	    fprintf(lockfp," %d", poll_interval);
	fclose(lockfp);

#ifdef HAVE_ATEXIT
	atexit(unlockit);
#else
	on_exit(unlockit, (char *)NULL);
#endif
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
	    if (ctl->active && !(implicitmode && ctl->server.skip))
	    {
#ifdef linux
		/* interface_approve() does its own error logging */
		if (!interface_approve(&ctl->server))
		    continue;
#endif /* linux */

#ifdef HAVE_GETHOSTBYNAME
		/*
		 * This functions partly as an optimization and partly
		 * as a probe to make sure our nameserver is still up.
		 * The multidrop case (especially) needs it.
		 */
		if (ctl->server.preauthenticate==A_KERBEROS_V4 || MULTIDROP(ctl))
		{
		    struct hostent	*namerec;

		    /* compute the canonical name of the host */
		    errno = 0;
		    namerec = gethostbyname(ctl->server.names->id);
		    if (namerec == (struct hostent *)NULL)
		    {
			error(0, errno,
				"skipping %s poll, ",
				ctl->server.names->id);
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
			free(ctl->server.canonical_name);
			ctl->server.canonical_name = xstrdup((char *)namerec->h_name);
		    }
		}
#endif /* HAVE_GETHOSTBYNAME */

		querystatus = query_host(ctl);
		if (!check_only)
		    update_str_lists(ctl);
#ifdef	linux
		if (ctl->server.monitor)
		    {
			/* Allow some time for the link to quiesce.  One
			 * second is usually sufficient, three is safe.
			 * Note:  this delay is important - don't remove!
			 */
			sleep(3);
			interface_note_activity(&ctl->server);
		    }
#endif
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
	    if (ctl->smtp_socket != -1)
	    {
		SMTP_quit(ctl->smtp_socket);
		close(ctl->smtp_socket);
		ctl->smtp_socket = -1;
	    }

	/*
	 * OK, we've polled.  Now sleep.
	 */
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
	    {
		struct itimerval ntimeout;

		ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
		ntimeout.it_value.tv_sec  = poll_interval;
		ntimeout.it_value.tv_usec = 0;

		setitimer(ITIMER_REAL,&ntimeout,NULL);
		signal(SIGALRM, donothing);
		pause();
		signal(SIGALRM, SIG_IGN);
		if (lastsig == SIGUSR1
			|| ((poll_interval && !getuid()) && lastsig == SIGHUP))
		{
#ifdef SYS_SIGLIST_DECLARED
		    error(0, 0, "awakened by %s", sys_siglist[lastsig]);
#else
		    error(0, 0, "awakened by signal %d", lastsig);
#endif
		}
	    }

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
    def_opts.smtp_socket = -1;

    def_opts.server.protocol = P_AUTO;
    def_opts.server.timeout = CLIENT_TIMEOUT;
    def_opts.remotename = user;
    save_str(&def_opts.smtphunt, -1, fetchmailhost);

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
		if (str_in_list(&ctl->server.names, argv[optind]))
		    goto foundit;

	    ctl = hostalloc(&cmd_opts);
	    save_str(&ctl->server.names, -1, argv[optind]);

	foundit:
	    ctl->active = TRUE;
	}

    /* if there's a defaults record, merge it and lose it */ 
    if (querylist && strcmp(querylist->server.names->id, "defaults") == 0)
    {
	for (ctl = querylist->next; ctl; ctl = ctl->next)
	    optmerge(ctl, querylist);
	querylist = querylist->next;
    }

    /* don't allow a defaults record after the first */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl != querylist && strcmp(ctl->server.names->id, "defaults") == 0)
	    exit(PS_SYNTAX);

    /* merge in wired defaults, do sanity checks and prepare internal fields */
    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	if (ctl->active && !(implicitmode && ctl->server.skip))
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
		    save_str_pair(&ctl->localnames, user, NULL);
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

	    /* compute server leaders for queries */
	    for (mp = querylist; mp && mp != ctl; mp = mp->next)
		if (strcmp(mp->server.names->id, ctl->server.names->id) == 0)
		{
		    ctl->server.lead_server = mp->server.lead_server;
		    goto no_new_server;
		}
	    ctl->server.lead_server = &(ctl->server);
	no_new_server:;

	    /* this code enables flags to be turned off */
#define DEFAULT(flag, dflt)	if (flag == FLAG_TRUE)\
	    				flag = TRUE;\
				else if (flag == FLAG_FALSE)\
					flag = FALSE;\
				else\
					flag = (dflt)
	    DEFAULT(ctl->keep, FALSE);
	    DEFAULT(ctl->flush, FALSE);
	    DEFAULT(ctl->fetchall, FALSE);
	    DEFAULT(ctl->rewrite, TRUE);
	    DEFAULT(ctl->stripcr, (ctl->mda != (char *)NULL)); 
	    DEFAULT(ctl->forcecr, FALSE);
	    DEFAULT(ctl->server.dns, TRUE);
	    DEFAULT(ctl->server.uidl, FALSE);
#undef DEFAULT

	    /* plug in the semi-standard way of indicating a mail address */
	    if (ctl->server.envelope == (char *)NULL)
		ctl->server.envelope = "X-Envelope-To:";

	    /* if no folders were specified, set up the null one as default */
	    if (!ctl->mailboxes)
		save_str(&ctl->mailboxes, -1, (char *)NULL);

	    /* maybe user overrode timeout on command line? */
	    if (ctl->server.timeout == -1)	
		ctl->server.timeout = CLIENT_TIMEOUT;

	    /* sanity checks */
	    if (ctl->server.port < 0)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, port number cannot be negative",
			       ctl->server.names->id);
		exit(PS_SYNTAX);
	    }
	    if (ctl->server.protocol == P_RPOP && ctl->server.port >= 1024)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, RPOP requires a privileged port",
			       ctl->server.names->id);
		exit(PS_SYNTAX);
	    }
	}
    }

    /* initialize UID handling */
    if ((st = prc_filecheck(idfile)) != 0)
	exit(st);
    else
	initialize_saved_lists(querylist, idfile);

    /* if cmd_logfile was explicitly set, use it to override logfile */
    if (cmd_logfile)
	logfile = cmd_logfile;

    /* likewise for poll_interval */
    if (cmd_daemon >= 0)
	poll_interval = cmd_daemon;

    /* check and daemon options are not compatible */
    if (check_only && poll_interval)
	poll_interval = 0;

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
	    if (ctl->smtp_socket != -1)
		SMTP_quit(ctl->smtp_socket);

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
#ifdef POP2_ENABLE
    case P_POP2: return("POP2"); break;
#endif /* POP2_ENABLE */
    case P_POP3: return("POP3"); break;
    case P_IMAP: return("IMAP"); break;
    case P_IMAP_K4: return("IMAP-K4"); break;
    case P_APOP: return("APOP"); break;
    case P_RPOP: return("RPOP"); break;
    case P_ETRN: return("ETRN"); break;
    default: return("unknown?!?"); break;
    }
}

/*
 * Sequence of protocols to try when autoprobing, most capable to least.
 */
#ifdef POP2_ENABLE
static const int autoprobe[] = {P_IMAP, P_POP3, P_POP2};
#else
static const int autoprobe[] = {P_IMAP, P_POP3};
#endif /* POP2_ENABLE */

static int query_host(struct query *ctl)
/* perform fetch transaction with single host */
{
    int i, st;

    if (poll_interval && ctl->server.interval) 
    {
	if (ctl->server.poll_count++ % ctl->server.interval) 
	{
	    if (outlevel == O_VERBOSE)
		fprintf(stderr,
		    "fetchmail: interval not reached, not querying %s\n",
		    ctl->server.names->id);
	    return PS_NOMAIL;
	}
    }

    if (outlevel == O_VERBOSE)
    {
	time_t now;

	time(&now);
	fprintf(stderr, "fetchmail: %s querying %s (protocol %s) at %s",
	    RELEASE_ID,
	    ctl->server.names->id, showproto(ctl->server.protocol), ctime(&now));
    }
    switch (ctl->server.protocol) {
    case P_AUTO:
	for (i = 0; i < sizeof(autoprobe)/sizeof(autoprobe[0]); i++)
	{
	    ctl->server.protocol = autoprobe[i];
	    if ((st = query_host(ctl)) == PS_SUCCESS || st == PS_NOMAIL || st == PS_AUTHFAIL)
		break;
	}
	ctl->server.protocol = P_AUTO;
	return(st);
	break;
    case P_POP2:
#ifdef POP2_ENABLE
	return(doPOP2(ctl));
#else
	fprintf(stderr, "POP2 support is not configured.\n");
	return(PS_PROTOCOL);
#endif /* POP2_ENABLE */
	break;
    case P_POP3:
    case P_APOP:
    case P_RPOP:
	return(doPOP3(ctl));
	break;
    case P_IMAP:
    case P_IMAP_K4:
	return(doIMAP(ctl));
	break;
    case P_ETRN:
	return(doETRN(ctl));
    default:
	error(0, 0, "unsupported protocol selected.");
	return(PS_PROTOCOL);
    }
}

void dump_params (struct query *ctl)
/* display query parameters in English */
{
    printf("Options for retrieving from %s@%s:\n",
	   ctl->remotename, visbuf(ctl->server.names->id));

    if (logfile)
	printf("  Logfile is %s\n", logfile);
    if (poll_interval)
	printf("  Poll interval is %d seconds\n", poll_interval);
    if (ctl->server.interval)
	printf("  Poll of this server will occur every %d intervals.\n",
	       ctl->server.interval);
#ifdef HAVE_GETHOSTBYNAME
    if (ctl->server.canonical_name)
	printf("  Canonical DNS name of server is %s.\n", ctl->server.canonical_name);
#endif /* HAVE_GETHOSTBYNAME */
    if (ctl->server.names->next)
    {
	struct idlist *idp;

	printf("  Predeclared mailserver aliases:");
	for (idp = ctl->server.names->next; idp; idp = idp->next)
	    printf(" %s", idp->id);
	putchar('\n');
    }
    if (ctl->server.skip || outlevel == O_VERBOSE)
	printf("  This host will%s be queried when no host is specified.\n",
	       ctl->server.skip ? " not" : "");
    if (!ctl->password)
	printf("  Password will be prompted for.\n");
    else if (outlevel == O_VERBOSE)
	if (ctl->server.protocol == P_APOP)
	    printf("  APOP secret = '%s'.\n", visbuf(ctl->password));
	else if (ctl->server.protocol == P_RPOP)
	    printf("  RPOP id = '%s'.\n", visbuf(ctl->password));
        else
	    printf("  Password = '%s'.\n", visbuf(ctl->password));
    if (ctl->server.protocol == P_POP3 
		&& ctl->server.port == KPOP_PORT
		&& ctl->server.preauthenticate == A_KERBEROS_V4)
	printf("  Protocol is KPOP");
    else
	printf("  Protocol is %s", showproto(ctl->server.protocol));
    if (ctl->server.port)
	printf(" (using port %d)", ctl->server.port);
    else if (outlevel == O_VERBOSE)
	printf(" (using default port)");
    if (ctl->server.uidl)
	printf(" (forcing UIDL use)");
    putchar('.');
    putchar('\n');
    if (ctl->server.preauthenticate == A_KERBEROS_V4)
	    printf("  Kerberos V4 preauthentication enabled.\n");
    if (ctl->server.timeout > 0)
	printf("  Server nonresponse timeout is %d seconds", ctl->server.timeout);
    if (ctl->server.timeout ==  CLIENT_TIMEOUT)
	printf(" (default).\n");
    else
	printf(".\n");
    if (ctl->server.localdomains)
    {
	struct idlist *idp;

	printf("  Local domains:");
	for (idp = ctl->server.localdomains; idp; idp = idp->next)
	    printf(" %s", idp->id);
	putchar('\n');
    }

    if (!ctl->mailboxes->id)
	printf("  Default mailbox selected.\n");
    else
    {
	struct idlist *idp;

	printf("  Selected mailboxes are:");
	for (idp = ctl->mailboxes; idp; idp = idp->next)
	    printf(" %s", idp->id);
	printf("\n");
    }
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
	   ctl->rewrite ? "en" : "dis",
	   ctl->rewrite ? "off" : "on");
    printf("  Carriage-return stripping is %sabled (--stripcr %s).\n",
	   ctl->stripcr ? "en" : "dis",
	   ctl->stripcr ? "on" : "off");
    printf("  Carriage-return forcing is %sabled (--forcecr %s).\n",
	   ctl->forcecr ? "en" : "dis",
	   ctl->forcecr ? "on" : "off");
    if (ctl->limit > 0)
	printf("  Message size limit is %d bytes (--limit %d).\n", 
	       ctl->limit, ctl->limit);
    else if (outlevel == O_VERBOSE)
	printf("  No message size limit (--limit 0).\n");
    if (ctl->fetchlimit > 0)
	printf("  Received-message limit is %d (--fetchlimit %d).\n",
	       ctl->fetchlimit, ctl->fetchlimit);
    else if (outlevel == O_VERBOSE)
	printf("  No received-message limit (--fetchlimit 0).\n");
    if (ctl->batchlimit > 0)
	printf("  SMTP message batch limit is %d.\n", ctl->batchlimit);
    else if (outlevel == O_VERBOSE)
	printf("  No SMTP message batch limit.\n");
    if (ctl->mda)
	printf("  Messages will be delivered with '%s.'\n", visbuf(ctl->mda));
    else
    {
	struct idlist *idp;

	printf("  Messages will be SMTP-forwarded to:");
	for (idp = ctl->smtphunt; idp; idp = idp->next)
	    printf(" %s", idp->id);
	printf("\n");
    }
    if (ctl->preconnect)
	printf("  Server connection will be preinitialized with '%s.'\n", visbuf(ctl->preconnect));
    else if (outlevel == O_VERBOSE)
	printf("  No preinitialization command.\n");
    if (!ctl->localnames)
	printf("  No localnames declared for this host.\n");
    else
    {
	struct idlist *idp;
	int count = 0;

	for (idp = ctl->localnames; idp; idp = idp->next)
	    ++count;

	printf("  %d local name(s) recognized.\n", count);
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

	printf("  DNS lookup for multidrop addresses is %sabled.\n",
	       ctl->server.dns ? "en" : "dis");

	if (count > 1)
	    if (ctl->server.envelope == STRING_DISABLED)
		printf("  Envelope-address routing is disabled\n");
	    else
		printf("  Envelope header is assumed to be: %s\n", ctl->server.envelope);
    }
#ifdef	linux
    if (ctl->server.interface)
	printf("  Connection must be through interface %s.\n", ctl->server.interface);
    else if (outlevel == O_VERBOSE)
	printf("  No interface requirement specified.\n");
    if (ctl->server.monitor)
	printf("  Polling loop will monitor %s.\n", ctl->server.monitor);
    else if (outlevel == O_VERBOSE)
	printf("  No monitor interface specified.\n");
#endif

    if (ctl->server.protocol > P_POP2)
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
