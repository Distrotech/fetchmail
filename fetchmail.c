/*
 * fetchmail.c -- main driver module for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>
#include <stdio.h>

#if defined(STDC_HEADERS)
#include <stdlib.h>
#include <string.h>
#endif

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <signal.h>
#include <pwd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_GETHOSTBYNAME
#include <netdb.h>
#endif /* HAVE_GETHOSTBYNAME */

#include "fetchmail.h"
#include "getopt.h"

#define DROPDEAD	6	/* maximum bad socket opens */

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
static int dump_options (struct query *);
static int query_host(struct query *);
static char *visbuf(const char *);
#endif

/* controls the detail level of status/progress messages written to stderr */
int outlevel;    	/* see the O_.* constants above */
int yydebug;		/* enable parse debugging */

/* daemon mode control */
int poll_interval;	/* poll interval in seconds */
char *logfile;		/* log file for daemon mode */
int quitmode;		/* if --quit was set */
int check_only;		/* if --probe was set */

/* miscellaneous global controls */
char *rcfile;		/* path name of rc file */
char *idfile;		/* UID list file */
int versioninfo;	/* emit only version info */
char *dfltuser;		/* invoking user */

static void termhook();
static char *lockfile;
static int popstatus;
static struct query *ctl;

RETSIGTYPE donothing(sig) int sig; {signal(sig, donothing);}

main (argc,argv)
int argc;
char **argv;
{ 
    int mboxfd, st, bkgd, lossage;
    struct query def_opts;
    int parsestatus, implicitmode;
    char *servername, *user, *home, *tmpdir, tmpbuf[BUFSIZ]; 
    struct passwd *pw;
    FILE	*lockfp;
    pid_t pid;

    memset(&def_opts, '\0', sizeof(struct query));

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

    def_opts.protocol = P_AUTO;
    def_opts.timeout = CLIENT_TIMEOUT;
    strcpy(def_opts.remotename, user);
    strcpy(def_opts.smtphost, "localhost");

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

    if (versioninfo)
	printf("This is fetchmail release %s\n", RELEASE_ID);

    /* this builds the host list */
    if (prc_parse_file(rcfile) != 0)
	exit(PS_SYNTAX);

    if (implicitmode = (optind >= argc))
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
		if (strcmp(ctl->servername, argv[optind]) == 0)
		    goto foundit;

	    ctl = hostalloc(&cmd_opts);
	    strcpy(ctl->servername, argv[optind]);

	foundit:
	    ctl->active = TRUE;
	}

    /* if there's a defaults record, merge it and lose it */ 
    if (querylist && strcmp(querylist->servername, "defaults") == 0)
    {
	for (ctl = querylist; ctl; ctl = ctl->next)
	    optmerge(ctl, querylist);
	querylist = querylist->next;
    }

    /* don't allow a defaults record after the first */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (strcmp(ctl->servername, "defaults") == 0)
	    exit(PS_SYNTAX);

    /* figure out who the default recipient should be */
    if (getuid() == 0)
	dfltuser = ctl->remotename;
    else
	dfltuser = user;

    /* merge in wired defaults, do sanity checks and prepare internal fields */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (ctl->active && !(implicitmode && ctl->skip))
	{
#ifdef HAVE_GETHOSTBYNAME
	    struct hostent	*namerec;
#endif /* HAVE_GETHOSTBYNAME */

	    /* merge in defaults */
	    optmerge(ctl, &def_opts);

	    /* keep lusers from shooting themselves in the foot :-) */
	    if (poll_interval && ctl->limit)
	    {
		fprintf(stderr,"fetchmail: you'd never see large messages!\n");
		exit(PS_SYNTAX);
	    }

	    /* check that delivery is going to a real local user */
	    if ((pw = getpwnam(user)) == (struct passwd *)NULL)
	    {
		fprintf(stderr,
			"fetchmail: can't default delivery to %s\n", user);
		exit(PS_SYNTAX);	/* has to be from bad rc file */
	    }
	    else
		ctl->uid = pw->pw_uid;

#ifdef HAVE_GETHOSTBYNAME
	    /* compute the canonical name of the host */
	    namerec = gethostbyname(ctl->servername);
	    if (namerec == (struct hostent *)NULL)
	    {
		fprintf(stderr,
			"fetchmail: can't get canonical name of host %s\n",
			ctl->servername);
		exit(PS_SYNTAX);
	    }
	    else
		ctl->canonical_name = xstrdup((char *)namerec->h_name);
#else
	    /* can't handle multidrop mailboxes unless we can do DNS lookups */
	    if (ctl->localnames && ctl->localnames->next)
	    {
		fputs("fetchmail: can't handle multidrop mailboxes without DNS\n",
			stderr);
		exit(PS_SYNTAX);
	    }
#endif /* HAVE_GETHOSTBYNAME */

	    /* sanity checks */
	    if (ctl->port < 0)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, port number cannot be negative",
			       ctl->servername);
		exit(PS_SYNTAX);
	    }

	    /* expand MDA commands */
	    if (!check_only && ctl->mda[0])
	    {
		char *argp;

		/* punch nulls into the delimiting whitespace in the args */
		for (argp = ctl->mda, ctl->mda_argcount = 1; *argp != '\0'; ctl->mda_argcount++)
		{
		    ctl->mda_argv[ctl->mda_argcount] = argp;
		    while (!(*argp == '\0' || isspace(*argp)))
			argp++;
		    if (*argp != '\0')
			*(argp++) = '\0';  
		}

		ctl->mda_argv[ctl->mda_argcount] = (char *)NULL;

		ctl->mda_argv[0] = ctl->mda_argv[1];
		if ((argp = strrchr(ctl->mda_argv[1], '/')) != (char *)NULL)
		    ctl->mda_argv[1] = argp + 1 ;
	    }
	}

    /* set up to do lock protocol */
    if ((tmpdir = getenv("TMPDIR")) == (char *)NULL)
	tmpdir = "/tmp";
    strcpy(tmpbuf, tmpdir);
    strcat(tmpbuf, "/fetchmail-");
    strcat(tmpbuf, user);

    /* initialize UID handling */
    if ((st = prc_filecheck(idfile)) != 0)
	exit(st);
    else
	initialize_saved_lists(querylist, idfile);

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
	    if (ctl->active && !(implicitmode && ctl->skip))
		dump_params(ctl);
	}
	if (querylist == NULL)
	    (void) fprintf(stderr,
		"No mailservers set up -- perhaps %s is missing?\n",
			  rcfile);
	exit(0);
    }
    else if (querylist == NULL) {
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
	    return(PS_EXCLUDE);
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
	else if (kill(pid, SIGHUP) == 0)
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
	     * croaks after the first kill probe above but before the SIGHUP
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
			       ctl->remotename, ctl->servername);
		(void) strncpy(ctl->password,
			       (char *)getpassword(tmpbuf),PASSWORDLEN-1);
	      }
	}

    /*
     * Maybe time to go to demon mode...
     */
    if (poll_interval)
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
    signal(SIGHUP, donothing);

    if ( (lockfp = fopen(lockfile,"w")) != NULL ) {
	fprintf(lockfp,"%d",getpid());
	if (poll_interval)
	    fprintf(lockfp," %d", poll_interval);
	fclose(lockfp);
    }

    /*
     * Query all hosts. If there's only one, the error return will
     * reflect the status of that transaction.
     */
    lossage = 0;
    do {

#ifdef HAVE_GETHOSTBYNAME
	sethostent(TRUE);	/* use TCP/IP for mailserver queries */
#endif /* HAVE_GETHOSTBYNAME */

	for (ctl = querylist; ctl; ctl = ctl->next)
	{
	    if (ctl->active && !(implicitmode && ctl->skip))
	    {
		popstatus = query_host(ctl);

		/*
		 * Under Linux, if fetchmail is run in daemon mode
		 * with the network inaccessible, each poll leaves a
		 * socket allocated but in CLOSE state (this is
		 * visible in netstat(1)'s output).  For some reason,
		 * these sockets aren't garbage-collected until
		 * fetchmail exits.  When whatever kernel table is
		 * involved fills up, fetchmail can no longer run even
		 * if the network is up.  This does not appear to be a
		 * socket leak in fetchmail.  To avoid this
		 * problem, fetchmail commits seppuku after five
		 * unsuccessful socket opens.
		 */
		if (popstatus == PS_SOCKET)
		    lossage++;
		else
		    lossage = 0;
		if (lossage >= DROPDEAD)
		{
		    fputs("fetchmail: exiting, network appears to be down\n",
			  stderr);
		    termhook(0);
		}

		if (!check_only)
		    update_uid_lists(ctl);
	    }
	}

#ifdef HAVE_GETHOSTBYNAME
	endhostent();		/* release TCP/IP connection to nameserver */
#endif /* HAVE_GETHOSTBYNAME */

	if (sleep(poll_interval))
	    (void) fputs("fetchmail: awakened by SIGHUP\n", stderr);
    } while
	(poll_interval);

    if (outlevel == O_VERBOSE)
	fprintf(stderr, "fetchmail: normal termination, status %d\n", popstatus);

    termhook(0);
    exit(popstatus);
}

void termhook(int sig)
/* to be executed on normal or signal-induced termination */
{
    if (sig != 0)
	fprintf(stderr, "terminated with signal %d\n", sig);

    if (!check_only)
	write_saved_lists(querylist, idfile);

    unlink(lockfile);
    exit(popstatus);
}

static char *showproto(proto)
/* protocol index to protocol name mapping */
int proto;
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

static int query_host(ctl)
/* perform fetch transaction with single host */
struct query *ctl;
{
    int i, st;

    if (outlevel == O_VERBOSE)
    {
	time_t now;

	time(&now);
	fprintf(stderr, "Querying %s (protocol %s) at %s",
	    ctl->servername, showproto(ctl->protocol), ctime(&now));
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
	fprintf(stderr,"fetchmail: unsupported protocol selected.\n");
	return(PS_PROTOCOL);
    }
}

int dump_params (ctl)
/* display query parameters in English */
struct query *ctl;	/* query parameter block */
{
    printf("Options for retrieving from %s@%s:\n",
	   ctl->remotename, visbuf(ctl->servername));
#ifdef HAVE_GETHOSTBYNAME
    printf("  Canonical DNS name of server is %s.\n", ctl->canonical_name);
#endif /* HAVE_GETHOSTBYNAME */
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
    {
	printf("  Protocol is %s", showproto(ctl->protocol));
    }
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
	printf("\n.");

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
	printf("  Message size limit is %d bytes\n", ctl->limit);
    else if (outlevel == O_VERBOSE)
	printf("  No message size limit\n");
    if (ctl->mda[0])
    {
	char **cp;

	printf("  Messages will be delivered with %s, args:",
	       visbuf(ctl->mda_argv[0]));
	for (cp = ctl->mda_argv+1; *cp; cp++)
	    printf(" %s", visbuf(*cp));
	putchar('\n');
    }
    else
	printf("  Messages will be SMTP-forwarded to '%s'.\n",
	       visbuf(ctl->smtphost));
    if (!ctl->localnames)
	printf("  No localnames declared for this host.\n");
    else
    {
	struct idlist *idp;
	int count = 0;

	for (idp = ctl->localnames; idp; idp = idp->next)
	    ++count;

	printf("  %d local names recognized.\n", count);
	if (outlevel == O_VERBOSE)
	    for (idp = ctl->localnames; idp; idp = idp->next)
		if (idp->val.id2)
		    fprintf(stderr, "\t%s -> %s\n", idp->id, idp->val.id2);
		else
		    fprintf(stderr, "\t%s\n", idp->id);
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
		    fprintf(stderr, "\t%s %s\n", ctl->servername, idp->id);
	}
}

int openmailpipe (argv)
/* open a one-way pipe to a mail delivery agent */
char *argv[];
{
    int pipefd [2];
    int childpid;

    if (pipe(pipefd) < 0) {
	perror("fetchmail: openmailpipe: pipe");
	return(-1);
    }
    if ((childpid = fork()) < 0) {
	perror("fetchmail: openmailpipe: fork");
	return(-1);
    }
    else if (childpid == 0) {

	/* in child process space */
	close(pipefd[1]);  /* close the 'write' end of the pipe */
	close(0);          /* get rid of inherited stdin */
	if (dup(pipefd[0]) != 0) {
	    fputs("fetchmail: openmailpipe: dup() failed\n",stderr);
	    exit(1);
	}

	execv(argv[0], argv + 1);

	/* if we got here, an error occurred */
	perror("fetchmail: openmailpipe: exec");
	_exit(PS_SYNTAX);

    }

    /* in the parent process space */
    close(pipefd[0]);  /* close the 'read' end of the pipe */
    return(pipefd[1]);
}

int closemailpipe (fd)
/* close the pipe to the mail delivery agent */
int fd;
{
    int err, status;
    int childpid;

    if (outlevel == O_VERBOSE)
	fprintf(stderr, "about to close pipe %d\n", fd);

    if ((err = close(fd)) != 0)
	perror("fetchmail: closemailpipe: close failed");

    childpid = wait(&status);

#if defined(WIFEXITED) && defined(WEXITSTATUS)
    /*
     * Try to pass up an error if the MDA returned nonzero status,
     * on the assumption that this means it was reporting failure.
     */
    if (WIFEXITED(status) == 0 || WEXITSTATUS(status) != 0)
    {
	perror("fetchmail: MDA exited abnormally or returned nonzero status");
	err = -1;
    }
#endif

    if (outlevel == O_VERBOSE)
	fprintf(stderr, "closed pipe %d\n", fd);
  
    return(err);
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

static char *visbuf(buf)
/* visibilize a given string */
const char *buf;
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
