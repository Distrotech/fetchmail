/*
 * fetchmail.c -- main driver module for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */
#include "config.h"

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
#else
#ifdef _AIX
 #pragma alloca
#endif
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
#ifdef HAVE_SETRLIMIT
#include <sys/resource.h>
#endif /* HAVE_SETRLIMIT */
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#endif /* HAVE_GETHOSTBYNAME */

#include "fetchmail.h"
#include "tunable.h"
#include "smtp.h"
#include "getopt.h"
#include "netrc.h"

#ifndef ENETUNREACH
#define ENETUNREACH   128       /* Interactive doesn't know this */
#endif /* ENETUNREACH */

/* prototypes for internal functions */
static int load_params(int, char **, int);
static void dump_params (struct runctl *runp, struct query *, flag implicit);
static int query_host(struct query *);

/* controls the detail level of status/progress messages written to stderr */
int outlevel;    	/* see the O_.* constants above */

/* miscellaneous global controls */
struct runctl run;	/* global controls for this run */
flag nodetach;		/* if TRUE, don't detach daemon process */
flag quitmode;		/* if --quit was set */
flag check_only;	/* if --probe was set */
flag versioninfo;	/* emit only version info */
char *user;		/* the name of the invoking user */
char *home;		/* invoking user's home directory */
char *program_name;	/* the name to prefix error messages with */
flag configdump;	/* dump control blocks for configurator */
char *fetchmailhost;	/* either `localhost' or the host FQDN */

#if NET_SECURITY
void *request = NULL;
int requestlen = 0;
#endif /* NET_SECURITY */

static char *lockfile;		/* name of lockfile */
static int querystatus;		/* status of query */
static int successes;		/* count number of successful polls */
static int lastsig;		/* last signal received */
static struct runctl cmd_run;	/* global options set from command line */

static void termhook();		/* forward declaration of exit hook */

#if 0
#define SLEEP_WITH_ALARM
#endif

#ifdef SLEEP_WITH_ALARM
/*
 * The function of this variable is to remove the window during which a
 * SIGALRM can hose the code (ALARM is triggered *before* pause() is called).
 * This is a bit of a kluge; the real right thing would use sigprocmask(),
 * sigsuspend().
 * This work around lets the interval timer trigger the first alarm after the
 * required interval and will then generate alarms all 5 seconds, until it
 * is certain, that the critical section (ie., the window) is left.
 */
#if defined(STDC_HEADERS)
static sig_atomic_t	alarm_latch = FALSE;
#else
/* assume int can be written in one atomic operation on non ANSI-C systems */
static int		alarm_latch = FALSE;
#endif

RETSIGTYPE gotsigalrm(sig)
int sig;
{
    signal(sig, gotsigalrm);
    lastsig = sig;
    alarm_latch = TRUE;
}
#endif /* SLEEP_WITH_ALARM */

RETSIGTYPE donothing(sig) int sig; {signal(sig, donothing); lastsig = sig;}

#ifdef HAVE_ON_EXIT
static void unlockit(int n, void *p)
#else
static void unlockit(void)
#endif
/* must-do actions for exit (but we can't count on being able to do malloc) */
{
    unlink(lockfile);
}

#ifdef __EMX__
/* Various EMX-specific definitions */
int itimerflag;
void itimerthread(void* dummy) {
  if (outlevel == O_VERBOSE)
    fprintf(stderr, "fetchmail: thread sleeping for %d sec.\n", poll_interval);
  while(1) {
    _sleep2(poll_interval*1000);
    kill((getpid()), SIGALRM);
  }
}
#endif

int main (int argc, char **argv)
{
    int st, bkgd = FALSE;
    int parsestatus, implicitmode = FALSE;
    FILE	*lockfp;
    struct query *ctl;
    netrc_entry *netrc_list;
    char *netrc_file, *tmpbuf;
    pid_t pid;

    envquery(argc, argv);

#define IDFILE_NAME	".fetchids"
    run.idfile = (char *) xmalloc(strlen(home)+strlen(IDFILE_NAME)+2);
    strcpy(run.idfile, home);
    strcat(run.idfile, "/");
    strcat(run.idfile, IDFILE_NAME);
  
    outlevel = O_NORMAL;

    if ((parsestatus = parsecmdline(argc,argv, &cmd_run, &cmd_opts)) < 0)
	exit(PS_SYNTAX);

    /* this hint to stdio should help messages come out in the right order */
    setvbuf(stdout, NULL, _IOLBF, MSGBUFSIZE);

    if (versioninfo)
    {
	printf("This is fetchmail release %s", RELEASE_ID);
#ifdef POP2_ENABLE
	printf("+POP2");
#endif /* POP2_ENABLE */
#ifndef POP3_ENABLE
	printf("-POP3");
#endif /* POP3_ENABLE */
#ifndef IMAP_ENABLE
	printf("-IMAP");
#endif /* IMAP_ENABLE */
#ifdef GSSAPI
	printf("+IMAP-GSS");
#endif /* GSSAPI */
#ifdef RPA_ENABLE
	printf("+RPA");
#endif /* RPA_ENABLE */
#ifdef SDPS_ENABLE
	printf("+SDPS");
#endif /* SDPS_ENABLE */
#ifndef ETRN_ENABLE
	printf("-ETRN");
#endif /* ETRN_ENABLE */
#if OPIE
	printf("+OPIE");
#endif /* OPIE */
#if INET6
	printf("+INET6");
#endif /* INET6 */
#if NET_SECURITY
	printf("+NETSEC");
#endif /* NET_SECURITY */
	putchar('\n');

	/* this is an attempt to help remote debugging */
	system("uname -a");
    }

    /* avoid parsing the config file if all we're doing is killing a daemon */ 
    if (!(quitmode && argc == 2))
	implicitmode = load_params(argc, argv, optind);

    /* set up to do lock protocol */
#define	FETCHMAIL_PIDFILE	"fetchmail.pid"
    tmpbuf = alloca(strlen(home) + strlen(FETCHMAIL_PIDFILE) + 3);
    if (!getuid())
	sprintf(tmpbuf, "%s/%s", PID_DIR, FETCHMAIL_PIDFILE);
    else {
	strcpy(tmpbuf, home);
	strcat(tmpbuf, "/.");
	strcat(tmpbuf, FETCHMAIL_PIDFILE);
    }
#undef FETCHMAIL_PIDFILE

    /* perhaps we just want to check options? */
    if (versioninfo)
    {
	printf("Taking options from command line");
	if (access(rcfile, 0))
	    printf("\n");
	else
	    printf(" and %s\n", rcfile);
	if (outlevel == O_VERBOSE)
	    printf("Lockfile at %s\n", tmpbuf);

	if (querylist == NULL)
	    (void) fprintf(stderr,
		"No mailservers set up -- perhaps %s is missing?\n", rcfile);
	else
	    dump_params(&run, querylist, implicitmode);
	exit(0);
    }

    /* dump options as a Python dictionary, for configurator use */
    if (configdump)
    {
	dump_config(&run, querylist);
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
    if (!(quitmode && argc == 2) && pid == -1 && querylist == NULL) {
	(void)fputs("fetchmail: no mailservers have been specified.\n",stderr);
	exit(PS_SYNTAX);
    }

    /* perhaps user asked us to kill the other fetchmail */
    if (quitmode)
    {
	if (pid == -1) 
	{
	    fprintf(stderr,"fetchmail: no other fetchmail is running\n");
	    if (argc == 2)
		exit(PS_EXCLUDE);
	}
	else if (kill(pid, SIGTERM) < 0)
	{
	    fprintf(stderr,"fetchmail: error killing %s fetchmail at %d; bailing out.\n",
		    bkgd ? "background" : "foreground", pid);
	    exit(PS_EXCLUDE);
	}
	else
	{
	    fprintf(stderr,"fetchmail: %s fetchmail at %d killed.\n",
		    bkgd ? "background" : "foreground", pid);
	    unlink(lockfile);
	    if (argc == 2)
		exit(0);
	    else
		pid = -1; 
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
    netrc_file = (char *) alloca (strlen (home) + 8);
    strcpy (netrc_file, home);
    strcat (netrc_file, "/.netrc");
    netrc_list = parse_netrc(netrc_file);

#ifdef HAVE_SETRLIMIT
    /*
     * Before getting passwords, disable core dumps unless -v -d0 mode is on.
     * Core dumps could otherwise contain passwords to be scavenged by a
     * cracker.
     */
    if (outlevel < O_VERBOSE || run.poll_interval > 0)
    {
	struct rlimit corelimit;
	corelimit.rlim_cur = 0;
	corelimit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &corelimit);
    }
#endif /* HAVE_SETRLIMIT */

    /* pick up interactively any passwords we need but don't have */ 
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl->active && !(implicitmode && ctl->server.skip)&&!ctl->password)
	{
	    if (ctl->server.preauthenticate == A_KERBEROS_V4 ||
		ctl->server.preauthenticate == A_KERBEROS_V5 ||
#ifdef GSSAPI
		ctl->server.protocol == P_IMAP_GSS ||
#endif /* GSSAPI */
		ctl->server.protocol == P_IMAP_K4)
		/* Server won't care what the password is, but there
		   must be some non-null string here.  */
		ctl->password = ctl->remotename;
	    else
	    {
		/* look up the host and account in the .netrc file. */
		netrc_entry *p = search_netrc(netrc_list,ctl->server.pollname);
		while (p && strcmp(p->account, ctl->remotename))
		    p = search_netrc(p->next, ctl->remotename);

		/* if we find a matching entry with a password, use it */
		if (p && p->password)
		    ctl->password = xstrdup(p->password);
	    }

	    if (ctl->server.protocol != P_ETRN && ctl->server.protocol != P_IMAP_K4
#ifdef GSSAPI
                && ctl->server.protocol != P_IMAP_GSS
#endif /* GSSAPI */
                && !ctl->password)
	    {
#define	PASSWORD_PROMPT	"Enter password for %s@%s: "
		tmpbuf = alloca(strlen(PASSWORD_PROMPT) +
					strlen(ctl->remotename) +
					strlen(ctl->server.pollname) + 1);
		(void) sprintf(tmpbuf, PASSWORD_PROMPT,
			       ctl->remotename, ctl->server.pollname);
		ctl->password = xstrdup((char *)getpassword(tmpbuf));
#undef	PASSWORD_PROMPT
	    }
	}

    /*
     * Maybe time to go to demon mode...
     */
#if defined(HAVE_SYSLOG)
    if (run.use_syslog)
    {
    	openlog(program_name, LOG_PID, LOG_MAIL);
	error_init(-1);
    }
    else
#endif
	error_init((run.poll_interval == 0 || nodetach) && !run.logfile);

    if (run.poll_interval)
    {
	if (!nodetach)
	    daemonize(run.logfile, termhook);
	error( 0, 0, "starting fetchmail %s daemon ", RELEASE_ID);

	/*
	 * We'll set up a handler for these when we're sleeping,
	 * but ignore them otherwise so as not to interrupt a poll.
	 */
	signal(SIGUSR1, SIG_IGN);
	if (run.poll_interval && !getuid())
	    signal(SIGHUP, SIG_IGN);
    }

    /* beyond here we don't want more than one fetchmail running per user */
    umask(0077);
    signal(SIGABRT, termhook);
    signal(SIGINT, termhook);
    signal(SIGTERM, termhook);
    signal(SIGALRM, termhook);
    signal(SIGPIPE, termhook);
    signal(SIGQUIT, termhook);

    /* here's the exclusion lock */
    if ((lockfp = fopen(lockfile,"w")) != NULL) {
	fprintf(lockfp,"%d",getpid());
	if (run.poll_interval)
	    fprintf(lockfp," %d", run.poll_interval);
	fclose(lockfp);

#ifdef HAVE_ATEXIT
	atexit(unlockit);
#endif
#ifdef HAVE_ON_EXIT
	on_exit(unlockit, (char *)NULL);
#endif
    }

    /*
     * Query all hosts. If there's only one, the error return will
     * reflect the status of that transaction.
     */
    do {
#if defined(HAVE_RES_SEARCH) && defined(USE_TCPIP_FOR_DNS)
	/*
	 * This was an efficiency hack that backfired.  The theory
	 * was that using TCP/IP for DNS queries would get us better
	 * reliability and shave off some per-UDP-packet costs.
	 * Unfortunately it interacted badly with diald, which effectively 
	 * filters out DNS queries over TCP/IP for reasons having to do
	 * with some obscure kernel problem involving bootstrapping of
	 * dynamically-addressed links.  I don't understand this mess
	 * and don't want to, so it's "See ya!" to this hack.
	 */
	sethostent(TRUE);	/* use TCP/IP for mailserver queries */
#endif /* HAVE_RES_SEARCH */

	batchcount = 0;
	for (ctl = querylist; ctl; ctl = ctl->next)
	{
	    if (ctl->active && !(implicitmode && ctl->server.skip))
	    {
		/* check skip interval first so that it counts all polls */
		if (run.poll_interval && ctl->server.interval) 
		{
		    if (ctl->server.poll_count++ % ctl->server.interval) 
		    {
			if (outlevel == O_VERBOSE)
			    fprintf(stderr,
				    "fetchmail: interval not reached, not querying %s\n",
				    ctl->server.pollname);
			continue;
		    }
		}

#if defined(linux) && !INET6
		/* interface_approve() does its own error logging */
		if (!interface_approve(&ctl->server))
		    continue;
#endif /* defined(linux) && !INET6 */

		querystatus = query_host(ctl);

		if (querystatus == PS_SUCCESS)
		{
		    successes++;
#ifdef POP3_ENABLE
		    if (!check_only)
			update_str_lists(ctl);

		   /* Save UID list to prevent re-fetch in case fetchmail 
		      recover from crash */
		    if (!check_only && outlevel == O_VERBOSE)
		    {
			write_saved_lists(querylist, run.idfile);
			if (outlevel == O_VERBOSE)
			    error(0, 0, "saved UID List");
		    }
#endif  /* POP3_ENABLE */
		}
		else if (!check_only && 
			 ((querystatus!=PS_NOMAIL) || (outlevel==O_VERBOSE)))
		    error(0, 0, "Query status=%d", querystatus);

#if defined(linux) && !INET6
		if (ctl->server.monitor)
		{
		    /*
		     * Allow some time for the link to quiesce.  One
		     * second is usually sufficient, three is safe.
		     * Note:  this delay is important - don't remove!
		     */
		    sleep(3);
		    interface_note_activity(&ctl->server);
		}
#endif /* defined(linux) && !INET6 */
	    }
	}

#if defined(HAVE_RES_SEARCH) && defined(USE_TCPIP_FOR_DNS)
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
	if (run.poll_interval)
	{
	    if (outlevel == O_VERBOSE)
	    {
		time_t	now;

		time(&now);
		fprintf(stderr, "fetchmail: sleeping at %s", ctime(&now));
	    }

	    /*
	     * With this simple hack, we make it possible for a foreground 
	     * fetchmail to wake up one in daemon mode.  What we want is the
	     * side effect of interrupting any sleep that may be going on,
	     * forcing fetchmail to re-poll its hosts.  The second line is
	     * for people who think all system daemons wake up on SIGHUP.
	     */
	    signal(SIGUSR1, donothing);
	    if (!getuid())
		signal(SIGHUP, donothing);

	    /*
	     * We can't use sleep(3) here because we need an alarm(3)
	     * equivalent in order to implement server nonresponse timeout.
	     * We'll just assume setitimer(2) is available since fetchmail
	     * has to have a BSDoid socket layer to work at all.
	     */
	    {
#ifndef __EMX__
#ifdef SLEEP_WITH_ALARM		/* not normally on */
		/* 
		 * This code stopped working under glibc-2, apparently due
		 * to the change in signal(2) semantics.  (The siginterrupt
		 * line, added later, should fix this problem.) John Stracke
		 * <francis@netscape.com> wrote:
		 *
		 * The problem seems to be that, after hitting the interval
		 * timer while talking to the server, the process no longer
		 * responds to SIGALRM.  I put in printf()s to see when it
		 * reached the pause() for the poll interval, and I checked
		 * the return from setitimer(), and everything seemed to be
		 * working fine, except that the pause() just ignored SIGALRM.
		 * I thought maybe the itimer wasn't being fired, so I hit
		 * it with a SIGALRM from the command line, and it ignored
		 * that, too.  SIGUSR1 woke it up just fine, and it proceeded
		 * to repoll--but, when the dummy server didn't respond, it
		 * never timed out, and SIGALRM wouldn't make it.
		 *
		 * (continued below...)
		 */
		struct itimerval ntimeout;

		ntimeout.it_interval.tv_sec = 5; /* repeat alarm every 5 secs */
		ntimeout.it_interval.tv_usec = 0;
		ntimeout.it_value.tv_sec  = run.poll_interval;
		ntimeout.it_value.tv_usec = 0;

		siginterrupt(SIGALRM, 1);
		alarm_latch = FALSE;
		signal(SIGALRM, gotsigalrm);	/* first trap signals */
		setitimer(ITIMER_REAL,&ntimeout,NULL);	/* then start timer */
		/* there is a very small window between the next two lines */
		/* which could result in a deadlock.  But this will now be  */
		/* caught by periodical alarms (see it_interval) */
		if (!alarm_latch)
		    pause();
		/* stop timer */
		ntimeout.it_interval.tv_sec = ntimeout.it_interval.tv_usec = 0;
		ntimeout.it_value.tv_sec  = ntimeout.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL,&ntimeout,NULL);	/* now stop timer */
		signal(SIGALRM, SIG_IGN);
#else
		/* 
		 * So the workaround I used is to make it sleep by using
		 * select() instead of setitimer()/pause().  select() is
		 * perfectly happy being called with a timeout and
		 * no file descriptors; it just sleeps until it hits the
		 * timeout.  The only concern I had was that it might
		 * implement its timeout with SIGALRM--there are some
		 * Unices where this is done, because select() is a library
		 * function--but apparently not.
		 */
                struct timeval timeout;

                timeout.tv_sec = run.poll_interval;
                timeout.tv_usec = 0;
		lastsig = 0;
                select(0,0,0,0, &timeout);
#endif
#else /* EMX */
		alarm_latch = FALSE;
		signal(SIGALRM, gotsigalrm);
		_beginthread(itimerthread, NULL, 32768, NULL);
		/* see similar code above */
		if (!alarm_latch)
		    pause();
		signal(SIGALRM, SIG_IGN);
#endif /* ! EMX */
		if (lastsig == SIGUSR1
			|| ((run.poll_interval && !getuid()) && lastsig == SIGHUP))
		{
#ifdef SYS_SIGLIST_DECLARED
		    error(0, 0, "awakened by %s", sys_siglist[lastsig]);
#else
		    error(0, 0, "awakened by signal %d", lastsig);
#endif
		}
	    }

	    /* now lock out interrupts again */
	    signal(SIGUSR1, SIG_IGN);
	    if (!getuid())
		signal(SIGHUP, SIG_IGN);

	    if (outlevel == O_VERBOSE)
	    {
		time_t	now;

		time(&now);
		fprintf(stderr, "fetchmail: awakened at %s", ctime(&now));
	    }
	}
    } while
	(run.poll_interval);

    if (outlevel == O_VERBOSE)
	fprintf(stderr,"fetchmail: normal termination, status %d\n",
		successes ? PS_SUCCESS : querystatus);

    termhook(0);
    exit(successes ? PS_SUCCESS : querystatus);
}

static void optmerge(struct query *h2, struct query *h1, int force)
/* merge two options records */
{
    /*
     * If force is off, modify h2 fields only when they're empty (treat h1
     * as defaults).  If force is on, modify each h2 field whenever h1
     * is nonempty (treat h1 as an override).  
     */
#define LIST_MERGE(dstl, srcl) if (force ? !!srcl : !dstl) \
    						free_str_list(&dstl), \
						append_str_list(&dstl, &srcl)
    LIST_MERGE(h2->server.localdomains, h1->server.localdomains);
    LIST_MERGE(h2->localnames, h1->localnames);
    LIST_MERGE(h2->mailboxes, h1->mailboxes);
    LIST_MERGE(h2->smtphunt, h1->smtphunt);
    LIST_MERGE(h2->antispam, h1->antispam);
#undef LIST_MERGE

#define FLAG_MERGE(fld) if (force ? !!h1->fld : !h2->fld) h2->fld = h1->fld
    FLAG_MERGE(server.via);
    FLAG_MERGE(server.protocol);
#if INET6
    FLAG_MERGE(server.service);
    FLAG_MERGE(server.netsec);
#else /* INET6 */
    FLAG_MERGE(server.port);
#endif /* INET6 */
    FLAG_MERGE(server.interval);
    FLAG_MERGE(server.preauthenticate);
    FLAG_MERGE(server.timeout);
    FLAG_MERGE(server.envelope);
    FLAG_MERGE(server.envskip);
    FLAG_MERGE(server.qvirtual);
    FLAG_MERGE(server.skip);
    FLAG_MERGE(server.dns);
    FLAG_MERGE(server.checkalias);
    FLAG_MERGE(server.uidl);

#ifdef linux
    FLAG_MERGE(server.interface);
    FLAG_MERGE(server.monitor);
    FLAG_MERGE(server.interface_pair);
#endif /* linux */

    FLAG_MERGE(wildcard);
    FLAG_MERGE(remotename);
    FLAG_MERGE(password);
    FLAG_MERGE(mda);
    FLAG_MERGE(smtpaddress);
    FLAG_MERGE(preconnect);
    FLAG_MERGE(postconnect);

    FLAG_MERGE(keep);
    FLAG_MERGE(flush);
    FLAG_MERGE(fetchall);
    FLAG_MERGE(rewrite);
    FLAG_MERGE(forcecr);
    FLAG_MERGE(stripcr);
    FLAG_MERGE(pass8bits);
    FLAG_MERGE(dropstatus);
    FLAG_MERGE(mimedecode);
    FLAG_MERGE(limit);
    FLAG_MERGE(warnings);
    FLAG_MERGE(fetchlimit);
    FLAG_MERGE(batchlimit);
    FLAG_MERGE(expunge);
#undef FLAG_MERGE
}

static int load_params(int argc, char **argv, int optind)
{
    int	implicitmode, st;
    struct passwd *pw;
    struct query def_opts, *ctl;

    memset(&def_opts, '\0', sizeof(struct query));
    def_opts.smtp_socket = -1;
    def_opts.smtpaddress = (char *)0;
    save_str(&def_opts.antispam, STRING_DUMMY, 0)->val.status.num = 571;
    save_str(&def_opts.antispam, STRING_DUMMY, 0)->val.status.num = 550;
    save_str(&def_opts.antispam, STRING_DUMMY, 0)->val.status.num = 501;

    def_opts.server.protocol = P_AUTO;
    def_opts.server.timeout = CLIENT_TIMEOUT;
    def_opts.warnings = WARNING_INTERVAL;
    def_opts.remotename = user;
    def_opts.expunge = 1;

    /* this builds the host list */
    if (prc_parse_file(rcfile, !versioninfo) != 0)
	exit(PS_SYNTAX);

    if ((implicitmode = (optind >= argc)))
    {
	for (ctl = querylist; ctl; ctl = ctl->next)
	    ctl->active = TRUE;
    }
    else
	for (; optind < argc; optind++) 
	{
	    flag	predeclared =  FALSE;

	    /*
	     * If hostname corresponds to a host known from the rc file,
	     * simply declare it active.  Otherwise synthesize a host
	     * record from command line and defaults
	     */
	    for (ctl = querylist; ctl; ctl = ctl->next)
		if (!strcmp(ctl->server.pollname, argv[optind])
			|| str_in_list(&ctl->server.akalist, argv[optind], TRUE))
		{
		    ctl->active = TRUE;
		    predeclared = TRUE;
		}

	    if (!predeclared)
	    {
		/*
		 * Allocate and link record without copying in
		 * command-line args; we'll do that with the optmerge
		 * call later on.
		 */
		ctl = hostalloc((struct query *)NULL);
		ctl->server.via =
		    ctl->server.pollname = xstrdup(argv[optind]);
		ctl->active = TRUE;
		ctl->server.lead_server = (struct hostdata *)NULL;
	    }
	}

    /*
     * If there's a defaults record, merge it and lose it.
     */ 
    if (querylist && strcmp(querylist->server.pollname, "defaults") == 0)
    {
	for (ctl = querylist->next; ctl; ctl = ctl->next)
	    optmerge(ctl, querylist, FALSE);
	querylist = querylist->next;
    }

    /* don't allow a defaults record after the first */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl != querylist && strcmp(ctl->server.pollname, "defaults") == 0)
	    exit(PS_SYNTAX);

    /* use localhost if we never fetch the FQDN of this host */
    fetchmailhost = "localhost";

    /* merge in wired defaults, do sanity checks and prepare internal fields */
    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	if (configdump || (ctl->active && !(implicitmode && ctl->server.skip)))
	{
	    /* merge in defaults */
	    optmerge(ctl, &def_opts, FALSE);

	    /* force command-line options */
	    optmerge(ctl, &cmd_opts, TRUE);

	    /*
	     * DNS support is required for some protocols.
	     *
	     * If we're using ETRN, the smtp hunt list is the list of
	     * systems we're polling on behalf of; these have to be 
	     * fully-qualified domain names.  The default for this list
	     * should be the FQDN of localhost.
	     *
	     * If we're using Kerberos for authentication, we need 
	     * the FQDN in order to generate capability keys.
	     */
	    if ((ctl->server.protocol == P_ETRN
			 || ctl->server.preauthenticate == A_KERBEROS_V4
			 || ctl->server.preauthenticate == A_KERBEROS_V5))
		if (strcmp(fetchmailhost, "localhost") == 0)
			fetchmailhost = host_fqdn();

	    /*
	     * Make sure we have a nonempty host list to forward to.
	     */
	    if (!ctl->smtphunt)
		save_str(&ctl->smtphunt, fetchmailhost, FALSE);

	    /* if `user' doesn't name a real local user, try to run as root */
	    if ((pw = getpwnam(user)) == (struct passwd *)NULL)
		ctl->uid = 0;
            else
		ctl->uid = pw->pw_uid;	/* for local delivery via MDA */
	    if (!ctl->localnames)	/* for local delivery via SMTP */
		save_str_pair(&ctl->localnames, user, NULL);

	    /* this code enables flags to be turned off */
#define DEFAULT(flag, dflt)	if (flag == FLAG_TRUE)\
	    				flag = TRUE;\
				else if (flag == FLAG_FALSE)\
					flag = FALSE;\
				else\
					flag = (dflt)
	    DEFAULT(ctl->keep, FALSE);
	    DEFAULT(ctl->fetchall, FALSE);
	    DEFAULT(ctl->flush, FALSE);
	    DEFAULT(ctl->rewrite, TRUE);
	    DEFAULT(ctl->stripcr, (ctl->mda != (char *)NULL)); 
	    DEFAULT(ctl->forcecr, FALSE);
	    DEFAULT(ctl->pass8bits, FALSE);
	    DEFAULT(ctl->dropstatus, FALSE);
	    DEFAULT(ctl->mimedecode, FALSE);
	    DEFAULT(ctl->server.dns, TRUE);
	    DEFAULT(ctl->server.uidl, FALSE);
	    DEFAULT(ctl->server.checkalias, FALSE);
#undef DEFAULT

#if !defined(HAVE_GETHOSTBYNAME) || !defined(HAVE_RES_SEARCH)
	    /* can't handle multidrop mailboxes unless we can do DNS lookups */
	    if (ctl->localnames && ctl->localnames->next && ctl->server.dns)
	    {
		ctl->server.dns = FALSE;
		fprintf(stderr, "fetchmail: warning: no DNS available to check multidrop fetches from %s\n", ctl->server.pollname);
	    }
#endif /* !HAVE_GETHOSTBYNAME || !HAVE_RES_SEARCH */

	    /*
	     *
	     * Compute the true name of the mailserver host.  
	     * There are two clashing cases here:
	     *
	     * (1) The poll name is a label, possibly on one of several
	     *     poll configurations for the same host.  In this case 
	     *     the `via' option will be present and give the true name.
	     *
	     * (2) The poll name is the true one, the via name is 
	     *     localhost.   This is going to be typical for ssh-using
	     *     configurations.
	     *
	     * We're going to assume the via name is true unless it's
	     * localhost.
	     */
	    if (ctl->server.via && strcmp(ctl->server.via, "localhost"))
		ctl->server.queryname = xstrdup(ctl->server.via);
	    else
		ctl->server.queryname = xstrdup(ctl->server.pollname);

	    /*
	     * We may have to canonicalize the server truename for later use.
	     * Do this just once for each lead server, if necessary, in order
	     * to minimize DNS round trips.
	     */
	    if (ctl->server.lead_server)
		ctl->server.truename = xstrdup(ctl->server.lead_server->truename);
#ifdef HAVE_GETHOSTBYNAME
	    else if (ctl->server.preauthenticate==A_KERBEROS_V4 ||
		ctl->server.preauthenticate==A_KERBEROS_V5 ||
		(ctl->server.dns && MULTIDROP(ctl)))
	    {
		struct hostent	*namerec;

		/* compute the canonical name of the host */
		errno = 0;
		namerec = gethostbyname(ctl->server.queryname);
		if (namerec == (struct hostent *)NULL)
		{
		    error(0, errno,
			  "couldn't find canonical DNS name of %s",
			  ctl->server.pollname);
		    exit(PS_DNS);
		}
		else
		    ctl->server.truename=xstrdup((char *)namerec->h_name);
	    }
#endif /* HAVE_GETHOSTBYNAME */
	    else
		ctl->server.truename = xstrdup(ctl->server.queryname);

	    /* if no folders were specified, set up the null one as default */
	    if (!ctl->mailboxes)
		save_str(&ctl->mailboxes, (char *)NULL, 0);

	    /* maybe user overrode timeout on command line? */
	    if (ctl->server.timeout == -1)	
		ctl->server.timeout = CLIENT_TIMEOUT;

#if !INET6
	    /* sanity checks */
	    if (ctl->server.port < 0)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, port number cannot be negative",
			       ctl->server.pollname);
		exit(PS_SYNTAX);
	    }
	    if (ctl->server.protocol == P_RPOP && ctl->server.port >= 1024)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, RPOP requires a privileged port",
			       ctl->server.pollname);
		exit(PS_SYNTAX);
	    }
#endif /* !INET6 */
	}
    }

    /* here's where we override globals */
    if (cmd_run.logfile)
	run.logfile = cmd_run.logfile;
    if (cmd_run.idfile)
	run.idfile = cmd_run.idfile;
    if (cmd_run.poll_interval >= 0)
	run.poll_interval = cmd_run.poll_interval;
    if (cmd_run.invisible)
	run.invisible = cmd_run.invisible;
    if (cmd_run.use_syslog)
	run.use_syslog = (cmd_run.use_syslog == FLAG_TRUE);

    /* check and daemon options are not compatible */
    if (check_only && run.poll_interval)
	run.poll_interval = 0;

#ifdef POP3_ENABLE
    /* initialize UID handling */
    if (!versioninfo && (st = prc_filecheck(run.idfile, !versioninfo)) != 0)
	exit(st);
    else
	initialize_saved_lists(querylist, run.idfile);
#endif /* POP3_ENABLE */

    /*
     * If the user didn't set a last-resort user to get misaddressed
     * multidrop mail, set an appropriate default here.
     */
    if (!run.postmaster)
	if (getuid())				/* ordinary user */
	    run.postmaster = user;
	else					/* root */
	    run.postmaster = "postmaster";

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
     * command acknowledge.  In theory we could enable the QUIT
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

#ifdef POP3_ENABLE
    if (!check_only)
	write_saved_lists(querylist, run.idfile);
#endif /* POP3_ENABLE */

    /* 
     * Craig Metz, the RFC1938 one-time-password guy, points out:
     * "Remember that most kernels don't zero pages before handing them to the
     * next process and many kernels share pages between user and kernel space.
     * You'd be very surprised what you can find from a short program to do a
     * malloc() and then dump the contents of the pages you got. By zeroing
     * the secrets at end of run (earlier if you can), you make sure the next
     * guy can't get the password/pass phrase."
     *
     * Right you are, Craig!
     */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl->password)
	  memset(ctl->password, '\0', strlen(ctl->password));

#if !defined(HAVE_ATEXIT) && !defined(HAVE_ON_EXIT)
    unlockit();
#endif

    exit(successes ? PS_SUCCESS : querystatus);
}

/*
 * Sequence of protocols to try when autoprobing, most capable to least.
 */
static const int autoprobe[] = 
{
#ifdef IMAP_ENABLE
    P_IMAP,
#endif /* IMAP_ENABLE */
#ifdef POP3_ENABLE
    P_POP3,
#endif /* POP3_ENABLE */
#ifdef POP2_ENABLE
    P_POP2
#endif /* POP2_ENABLE */
};

static int query_host(struct query *ctl)
/* perform fetch transaction with single host */
{
    int i, st;

    if (outlevel == O_VERBOSE)
    {
	time_t now;

	time(&now);
	fprintf(stderr, "fetchmail: %s querying %s (protocol %s) at %s",
	    RELEASE_ID,
	    ctl->server.pollname, showproto(ctl->server.protocol), ctime(&now));
    }
    switch (ctl->server.protocol) {
    case P_AUTO:
	for (i = 0; i < sizeof(autoprobe)/sizeof(autoprobe[0]); i++)
	{
	    ctl->server.protocol = autoprobe[i];
	    if ((st = query_host(ctl)) == PS_SUCCESS || st == PS_NOMAIL || st == PS_AUTHFAIL || st == PS_LOCKBUSY || st == PS_SMTP)
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
#ifdef POP3_ENABLE
	return(doPOP3(ctl));
#else
	fprintf(stderr, "POP3 support is not configured.\n");
	return(PS_PROTOCOL);
#endif /* POP3_ENABLE */
	break;
    case P_IMAP:
    case P_IMAP_K4:
#ifdef GSSAPI
    case P_IMAP_GSS:
#endif /* GSSAPI */
#ifdef IMAP_ENABLE
	return(doIMAP(ctl));
#else
	fprintf(stderr, "IMAP support is not configured.\n");
	return(PS_PROTOCOL);
#endif /* IMAP_ENABLE */
	break;
    case P_ETRN:
#ifndef ETRN_ENABLE
	fprintf(stderr, "ETRN support is not configured.\n");
	return(PS_PROTOCOL);
#else
#ifdef HAVE_GETHOSTBYNAME
	return(doETRN(ctl));
#else
	fprintf(stderr, "Cannot support ETRN without gethostbyname(2).\n");
	return(PS_PROTOCOL);
#endif /* HAVE_GETHOSTBYNAME */
#endif /* ETRN_ENABLE */
    default:
	error(0, 0, "unsupported protocol selected.");
	return(PS_PROTOCOL);
    }
}

void dump_params (struct runctl *runp, struct query *querylist, flag implicit)
/* display query parameters in English */
{
    struct query *ctl;

    if (runp->poll_interval)
	printf("Poll interval is %d seconds\n", runp->poll_interval);
    if (runp->logfile)
	printf("Logfile is %s\n", runp->logfile);
    if (strcmp(runp->idfile, IDFILE_NAME))
	printf("Idfile is %s\n", runp->idfile);
#if defined(HAVE_SYSLOG)
    if (runp->use_syslog)
	printf("Progress messages will be logged via syslog\n");
#endif
    if (runp->invisible)
	printf("Fetchmail will masquerade and will not generate Received\n");
    if (runp->postmaster)
	printf("Fetchmail will forward misaddressed multidrop messages to %s.\n",
	       runp->postmaster);

    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	if (!ctl->active || (implicit && ctl->server.skip))
	    continue;

	printf("Options for retrieving from %s@%s:\n",
	       ctl->remotename, visbuf(ctl->server.pollname));

	if (ctl->server.via && (ctl->server.protocol != P_ETRN))
	    printf("  Mail will be retrieved via %s\n", ctl->server.via);

	if (ctl->server.interval)
	    printf("  Poll of this server will occur every %d intervals.\n",
		   ctl->server.interval);
	if (ctl->server.truename)
	    printf("  True name of server is %s.\n", ctl->server.truename);
	if (ctl->server.skip || outlevel == O_VERBOSE)
	    printf("  This host will%s be queried when no host is specified.\n",
		   ctl->server.skip ? " not" : "");
	/*
	 * Don't poll for password when there is one or when using the ETRN
	 * or IMAP-GSS protocol
	 */
	if (!ctl->password && (ctl->server.protocol != P_ETRN)
#ifdef GSSAPI
            && (ctl->server.protocol != P_IMAP_GSS)
#endif /* GSSAPI */
        )
	    printf("  Password will be prompted for.\n");
	else if (outlevel == O_VERBOSE)
	    if (ctl->server.protocol == P_APOP)
		printf("  APOP secret = \"%s\".\n", visbuf(ctl->password));
	    else if (ctl->server.protocol == P_RPOP)
		printf("  RPOP id = \"%s\".\n", visbuf(ctl->password));
	    else
		printf("  Password = \"%s\".\n", visbuf(ctl->password));
	if (ctl->server.protocol == P_POP3 
#if INET6
	    && !strcmp(ctl->server.service, KPOP_PORT)
#else /* INET6 */
	    && ctl->server.port == KPOP_PORT
#endif /* INET6 */
	    && (ctl->server.preauthenticate == A_KERBEROS_V4 ||
		ctl->server.preauthenticate == A_KERBEROS_V5))
	    printf("  Protocol is KPOP");
	else
	    printf("  Protocol is %s", showproto(ctl->server.protocol));
#if INET6
	if (ctl->server.service)
	    printf(" (using service %s)", ctl->server.service);
	if (ctl->server.netsec)
	    printf(" (using network security options %s)", ctl->server.netsec);
#else /* INET6 */
	if (ctl->server.port)
	    printf(" (using port %d)", ctl->server.port);
#endif /* INET6 */
	else if (outlevel == O_VERBOSE)
	    printf(" (using default port)");
	if (ctl->server.uidl && (ctl->server.protocol != P_ETRN))
	    printf(" (forcing UIDL use)");
	putchar('.');
	putchar('\n');
	if (ctl->server.preauthenticate == A_KERBEROS_V4)
	    printf("  Kerberos V4 preauthentication enabled.\n");
	if (ctl->server.preauthenticate == A_KERBEROS_V5)
	    printf("  Kerberos V5 preauthentication enabled.\n");
	if (ctl->server.timeout > 0)
	    printf("  Server nonresponse timeout is %d seconds", ctl->server.timeout);
	if (ctl->server.timeout ==  CLIENT_TIMEOUT)
	    printf(" (default).\n");
	else
	    printf(".\n");

	if (ctl->server.protocol != P_ETRN) {
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
		printf("  Carriage-return stripping is %sabled (stripcr %s).\n",
		       ctl->stripcr ? "en" : "dis",
		       ctl->stripcr ? "on" : "off");
		printf("  Carriage-return forcing is %sabled (forcecr %s).\n",
		       ctl->forcecr ? "en" : "dis",
		       ctl->forcecr ? "on" : "off");
		printf("  Interpretation of Content-Transfer-Encoding is %sabled (pass8bits %s).\n",
		       ctl->pass8bits ? "dis" : "en",
		       ctl->pass8bits ? "on" : "off");
		printf("  MIME decoding is %sabled (mimedecode %s).\n",
		       ctl->mimedecode ? "en" : "dis",
		       ctl->mimedecode ? "on" : "off");
		printf("  Nonempty Status lines will be %s (dropstatus %s)\n",
		       ctl->dropstatus ? "discarded" : "kept",
		       ctl->dropstatus ? "on" : "off");
		if (NUM_NONZERO(ctl->limit))
		{
		    if (NUM_NONZERO(ctl->limit))
			printf("  Message size limit is %d bytes (--limit %d).\n", 
			       ctl->limit, ctl->limit);
		    else if (outlevel == O_VERBOSE)
			printf("  No message size limit (--limit 0).\n");
		    if (run.poll_interval > 0)
			printf("  Message size warning interval is %d seconds (--warnings %d).\n", 
			       ctl->warnings, ctl->warnings);
		    else if (outlevel == O_VERBOSE)
			printf("  Size warnings on every poll (--warnings 0).\n");
		}
		if (NUM_NONZERO(ctl->fetchlimit))
		    printf("  Received-message limit is %d (--fetchlimit %d).\n",
			   ctl->fetchlimit, ctl->fetchlimit);
		else if (outlevel == O_VERBOSE)
		    printf("  No received-message limit (--fetchlimit 0).\n");
		if (NUM_NONZERO(ctl->batchlimit))
		    printf("  SMTP message batch limit is %d.\n", ctl->batchlimit);
		else if (outlevel == O_VERBOSE)
		    printf("  No SMTP message batch limit (--batchlimit 0).\n");
		if (ctl->server.protocol == P_IMAP)
		    if (NUM_NONZERO(ctl->expunge))
			printf("  Deletion interval between expunges is %d (--expunge %d).\n", ctl->expunge, ctl->expunge);
		    else if (outlevel == O_VERBOSE)
			printf("  No expunges (--expunge 0).\n");
	}
	if (ctl->mda && (ctl->server.protocol != P_ETRN))
	    printf("  Messages will be delivered with \"%s\".\n", visbuf(ctl->mda));
	else
	{
	    struct idlist *idp;

	    printf("  Messages will be SMTP-forwarded to:");
	    for (idp = ctl->smtphunt; idp; idp = idp->next)
	    {
                printf(" %s", idp->id);
		if (!idp->val.status.mark)
		    printf(" (default)");
	    }
	    printf("\n");
	    if (ctl->smtpaddress)
		printf("  Host part of MAIL FROM line will be %s\n",
		       ctl->smtpaddress);
	}
	if (ctl->server.protocol != P_ETRN)
	{
		if (ctl->antispam != (struct idlist *)NULL)
		{
		    struct idlist *idp;

		    printf("  Recognized listener spam block responses are:",
			   ctl->antispam);
		    for (idp = ctl->antispam; idp; idp = idp->next)
			printf(" %d", idp->val.status.num);
		    printf("\n");
		}
		else if (outlevel == O_VERBOSE)
		    printf("  Spam-blocking disabled\n");
	}
	if (ctl->preconnect)
	    printf("  Server connection will be brought up with \"%s\".\n",
		   visbuf(ctl->preconnect));
	else if (outlevel == O_VERBOSE)
	    printf("  No pre-connection command.\n");
	if (ctl->postconnect)
	    printf("  Server connection will be taken down with \"%s\".\n",
		   visbuf(ctl->postconnect));
	else if (outlevel == O_VERBOSE)
	    printf("  No post-connection command.\n");
	if (ctl->server.protocol != P_ETRN) {
		if (!ctl->localnames)
		    printf("  No localnames declared for this host.\n");
		else
		{
		    struct idlist *idp;
		    int count = 0;

		    for (idp = ctl->localnames; idp; idp = idp->next)
			++count;

		    if (count > 1 || ctl->wildcard)
			printf("  Multi-drop mode: ");
		    else
			printf("  Single-drop mode: ");

		    printf("%d local name(s) recognized.\n", count);
		    if (outlevel == O_VERBOSE)
		    {
			for (idp = ctl->localnames; idp; idp = idp->next)
			    if (idp->val.id2)
				printf("\t%s -> %s\n", idp->id, idp->val.id2);
			    else
				printf("\t%s\n", idp->id);
			if (ctl->wildcard)
			    fputs("\t*\n", stdout);
		    }

		    if (count > 1 || ctl->wildcard)
		    {
			printf("  DNS lookup for multidrop addresses is %sabled.\n",
			       ctl->server.dns ? "en" : "dis");
			if (ctl->server.dns)
			{
			    printf("  Server aliases will be compared with multidrop addresses by ");
	       		    if (ctl->server.checkalias)
				printf("IP address.\n");
			    else
				printf("name.\n");
			}
			if (ctl->server.envelope == STRING_DISABLED)
			    printf("  Envelope-address routing is disabled\n");
			else
			{
			    printf("  Envelope header is assumed to be: %s\n",
				   ctl->server.envelope ? ctl->server.envelope:"Received");
			    if (ctl->server.envskip > 1 || outlevel >= O_VERBOSE)
				printf("  Number of envelope header to be parsed: %d\n",
				       ctl->server.envskip);
			    if (ctl->server.qvirtual)
				printf("  Prefix %s will be removed from user id\n",
				       ctl->server.qvirtual);
			    else if (outlevel >= O_VERBOSE) 
				printf("  No prefix stripping\n");
			}

			if (ctl->server.akalist)
			{
			    struct idlist *idp;

			    printf("  Predeclared mailserver aliases:");
			    for (idp = ctl->server.akalist; idp; idp = idp->next)
				printf(" %s", idp->id);
			    putchar('\n');
			}
			if (ctl->server.localdomains)
			{
			    struct idlist *idp;

			    printf("  Local domains:");
			    for (idp = ctl->server.localdomains; idp; idp = idp->next)
				printf(" %s", idp->id);
			    putchar('\n');
			}
		    }
		}
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

	if (ctl->server.protocol > P_POP2 && (ctl->server.protocol != P_ETRN))
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
}

/* fetchmail.c ends here */
