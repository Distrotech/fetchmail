/*
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       fetchmail.c
  project:      fetchmail
  programmer:   Eric S. Raymond <esr@thyrsus.com>
  description:	main driver module for fetchmail

 ***********************************************************************/


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

#include "fetchmail.h"
#include "getopt.h"

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
static int showversioninfo (void);
static int dump_options (struct hostrec *queryctl);
static int query_host(struct hostrec *queryctl);
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

/*********************************************************************
  function:      main
  description:   main driver routine 
  arguments:     
    argc         argument count as passed by runtime startup code.
    argv         argument strings as passed by runtime startup code.

  return value:  an exit status code for the shell -- see the 
                 PS_.* constants defined above.
  calls:         parsecmdline, setdefaults, openuserfolder, doPOP2.
  globals:       none.
 *********************************************************************/

static void termhook();
static char *lockfile;
static int popstatus;
static struct hostrec *hostp;

main (argc,argv)
int argc;
char **argv;
{ 
    int mboxfd, st;
    struct hostrec def_opts;
    int parsestatus, implicitmode;
    char *servername, *user, *home, *tmpdir, tmpbuf[BUFSIZ]; 
    FILE	*lockfp;
    pid_t pid;

    memset(&def_opts, '\0', sizeof(struct hostrec));

    if ((user = getenv("USER")) == (char *)NULL)
        user = getenv("LOGNAME");

    if ((user == (char *)NULL) || (home = getenv("HOME")) == (char *)NULL)
    {
	struct passwd *pw;

	if ((pw = getpwuid(getuid())) != NULL)
	{
	    user = pw->pw_name;
	    home = pw->pw_dir;
	}
	else
	{
	    fprintf(stderr,"I can't find your name and home directory!\n");
	    exit(PS_UNDEFINED);
	}
    }

    def_opts.protocol = P_AUTO;

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
	showversioninfo();

    /* this builds the host list */
    if (prc_parse_file(rcfile) != 0)
	exit(PS_SYNTAX);

    if (implicitmode = (optind >= argc))
    {
	for (hostp = hostlist; hostp; hostp = hostp->next)
	    hostp->active = TRUE;
    }
    else
	for (; optind < argc; optind++) 
	{
	    /*
	     * If hostname corresponds to a host known from the rc file,
	     * simply declare it active.  Otherwise synthesize a host
	     * record from command line and defaults
	     */
	    for (hostp = hostlist; hostp; hostp = hostp->next)
		if (strcmp(hostp->servername, argv[optind]) == 0)
		    goto foundit;

	    hostp = hostalloc(&cmd_opts);
	    strcpy(hostp->servername, argv[optind]);

	foundit:
	    hostp->active = TRUE;
	}

    /* if there's a defaults record, merge it and lose it */ 
    if (hostlist && strcmp(hostlist->servername, "defaults") == 0)
    {
	for (hostp = hostlist; hostp; hostp = hostp->next)
	    optmerge(hostp, hostlist);
	hostlist = hostlist->next;
    }

    /* don't allow a defaults record after the first */
    for (hostp = hostlist; hostp; hostp = hostp->next)
	if (strcmp(hostp->servername, "defaults") == 0)
	    exit(PS_SYNTAX);

    /* merge in wired defaults, do sanity checks and prepare internal fields */
    for (hostp = hostlist; hostp; hostp = hostp->next)
	if (hostp->active && !(implicitmode && hostp->skip))
	{
	    /* merge in defaults */
	    optmerge(hostp, &def_opts);

	    /* if rc file didn't supply a localname, default appropriately */
	    if (!hostp->localname[0])
		strcpy(hostp->localname, hostp->remotename);

	    /* sanity checks */
	    if (hostp->port < 0)
	    {
		(void) fprintf(stderr,
			       "%s configuration invalid, port number cannot be negative",
			       hostp->servername);
		exit(PS_SYNTAX);
	    }

	    /* expand MDA commands */
	    if (hostp->mda[0])
	    {
		int argi;
		char *argp;

		/* expand the %s escape if any before parsing */
		sprintf(hostp->mdabuf, hostp->mda, hostp->localname);

		/* now punch nulls into the delimiting whitespace in the args */
		for (argp = hostp->mdabuf, argi = 1; *argp != '\0'; argi++)
		{
		    hostp->mda_argv[argi] = argp;
		    while (!(*argp == '\0' || isspace(*argp)))
			argp++;
		    if (*argp != '\0')
			*(argp++) = '\0';  
		}

		hostp->mda_argv[argi] = (char *)NULL;

		hostp->mda_argv[0] = hostp->mda_argv[1];
		if ((argp = strrchr(hostp->mda_argv[1], '/')) != (char *)NULL)
		    hostp->mda_argv[1] = argp + 1 ;
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
	initialize_saved_lists(hostlist, idfile);

    /* perhaps we just want to check options? */
    if (versioninfo) {
	    printf("Taking options from command line");
	    if (access(rcfile, 0))
		printf("\n");
	    else
		printf(" and %s\n", rcfile);
	    if (outlevel == O_VERBOSE)
		printf("Lockfile at %s\n", tmpbuf);
	for (hostp = hostlist; hostp; hostp = hostp->next) {
	    if (hostp->active && !(implicitmode && hostp->skip))
		dump_params(hostp);
	}
	if (hostlist == NULL)
	    (void) fprintf(stderr,
		"No mailservers set up -- perhaps %s is missing?\n",
			  rcfile);
	exit(0);
    }
    else if (hostlist == NULL) {
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
	fscanf(lockfp,"%d",&pid);

	if (kill(pid, 0) == -1) {
	    fprintf(stderr,"fetchmail: removing stale lockfile\n");
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
	    fprintf(stderr,"fetchmail: error killing fetchmail at %d.\n",pid);
	    exit(PS_EXCLUDE);
	}
	else
	{
	    fprintf(stderr,"fetchmail: fetchmail at %d killed.\n", pid);
	    remove(lockfile);
	    exit(0);
	}
    }

    /* otherwise die if another fetchmail is running */
    if (pid != -1)
    {
	fprintf(stderr,
		"fetchmail: another fetchmail is running at pid %d.\n", pid);
	return(PS_EXCLUDE);
    }

    /* pick up interactively any passwords we need but don't have */ 
    for (hostp = hostlist; hostp; hostp = hostp->next)
	if (hostp->active && !(implicitmode && hostp->skip) && !hostp->password[0])
	{
	    if (hostp->authenticate == A_KERBEROS)
	      /* Server won't care what the password is, but there
		 must be some non-null string here.  */
	      (void) strncpy(hostp->password, 
			     hostp->remotename, PASSWORDLEN-1);
	    else
	      {
		(void) sprintf(tmpbuf, "Enter password for %s@%s: ",
			       hostp->remotename, hostp->servername);
		(void) strncpy(hostp->password,
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
    signal(SIGHUP, termhook);
    signal(SIGPIPE, termhook);
    signal(SIGQUIT, termhook);
    if ( (lockfp = fopen(lockfile,"w")) != NULL ) {
	fprintf(lockfp,"%d",getpid());
	fclose(lockfp);
    }

    /*
     * Query all hosts. If there's only one, the error return will
     * reflect the status of that transaction.
     */
    do {
	for (hostp = hostlist; hostp; hostp = hostp->next) {
	    if (hostp->active && !(implicitmode && hostp->skip))
	    {
		popstatus = query_host(hostp);
 		update_uid_lists(hostp);
	    }
	}

	sleep(poll_interval);
    } while
	(poll_interval);

    if (outlevel == O_VERBOSE)
	fprintf(stderr, "normal termination, status %d\n", popstatus);

    termhook(0);
    exit(popstatus);
}

void termhook(int sig)
/* to be executed on normal or signal-induced termination */
{
    if (sig != 0)
	fprintf(stderr, "terminated with signal %d\n", sig);

    write_saved_lists(hostlist, idfile);

    unlink(lockfile);
    exit(popstatus);
}

/*********************************************************************
  function:      showproto
  description:   protocol index to name mapping
  arguments:
    proto        protocol index
  return value:  string name of protocol
  calls:         none.
  globals:       none.
 *********************************************************************/

static char *showproto(proto)
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

static int query_host(queryctl)
/* perform fetch transaction with single host */
struct hostrec *queryctl;
{
    int i, st;

    if (outlevel == O_VERBOSE)
    {
	time_t now;

	time(&now);
	fprintf(stderr, "Querying %s (protocol %s) at %s",
	    queryctl->servername, showproto(queryctl->protocol), ctime(&now));
    }
    switch (queryctl->protocol) {
    case P_AUTO:
	for (i = 0; i < sizeof(autoprobe)/sizeof(autoprobe[0]); i++)
	{
	    queryctl->protocol = autoprobe[i];
	    if ((st = query_host(queryctl)) == PS_SUCCESS || st == PS_NOMAIL || st == PS_AUTHFAIL)
		break;
	}
	queryctl->protocol = P_AUTO;
	return(st);
	break;
    case P_POP2:
	return(doPOP2(queryctl));
	break;
    case P_POP3:
    case P_APOP:
	return(doPOP3(queryctl));
	break;
    case P_IMAP:
	return(doIMAP(queryctl));
	break;
    default:
	fprintf(stderr,"fetchmail: unsupported protocol selected.\n");
	return(PS_PROTOCOL);
    }
}
 
/*********************************************************************
  function:      showversioninfo
  description:   display program release
  arguments:     none.
  return value:  none.
  calls:         none.
  globals:       none.
 *********************************************************************/

static int showversioninfo()
{
    printf("This is fetchmail release %s\n",RELEASE_ID);
}

/*********************************************************************
  function:      dump_params
  description:   display program options in English
  arguments:
    queryctl      merged options

  return value:  none.
  calls:         none.
  globals:       outlimit.
*********************************************************************/

int dump_params (queryctl)
struct hostrec *queryctl;
{
    printf("Options for %s retrieving from %s:\n",
	   hostp->localname, hostp->servername);
    if (queryctl->skip || outlevel == O_VERBOSE)
	printf("  This host will%s be queried when no host is specified.\n",
	       queryctl->skip ? " not" : "");
    printf("  Username = '%s'\n", queryctl->remotename);
    if (queryctl->password[0] == '\0')
	printf("  Password will be prompted for.\n");
    else if (outlevel == O_VERBOSE)
	if (queryctl->protocol == P_APOP)
	    printf("  APOP secret = '%s'\n", queryctl->password);
        else
	    printf("  Password = '%s'\n", queryctl->password);
    if (queryctl->protocol == P_POP3 && queryctl->port == KPOP_PORT)
	printf("  Protocol is KPOP");
    else
	printf("  Protocol is %s", showproto(queryctl->protocol));
    if (queryctl->port)
	printf(" (using port %d)", queryctl->port);
    else if (outlevel == O_VERBOSE)
	printf(" (using default port)");
    putchar('\n');

    printf("  Fetched messages will%s be kept on the server (--keep %s).\n",
	   queryctl->keep ? "" : " not",
	   queryctl->keep ? "on" : "off");
    printf("  %s messages will be retrieved (--all %s).\n",
	   queryctl->fetchall ? "All" : "Only new",
	   queryctl->fetchall ? "on" : "off");
    printf("  Old messages will%s be flushed before message retrieval (--flush %s).\n",
	   queryctl->flush ? "" : " not",
	   queryctl->flush ? "on" : "off");
    printf("  Rewrite of server-local addresses is %sabled (--norewrite %s)\n",
	   queryctl->norewrite ? "dis" : "en",
	   queryctl->norewrite ? "on" : "off");
    if (queryctl->mda[0])
    {
	char **cp;

	printf("  Messages will be delivered with %s, args:",
	       queryctl->mda_argv[0]);
	for (cp = queryctl->mda_argv+1; *cp; cp++)
	    printf(" %s", *cp);
	putchar('\n');
    }
    else
	printf("  Messages will be SMTP-forwarded to '%s'\n", queryctl->smtphost);
    if (queryctl->protocol > P_POP2)
	if (!queryctl->oldsaved)
	    printf("  No UIDs saved from this host.\n");
	else
	{
	    struct idlist *idp;
	    int count = 0;

	    for (idp = hostp->oldsaved; idp; idp = idp->next)
		++count;

	    printf("  %d UIDs saved.\n", count);
	    if (outlevel == O_VERBOSE)
		for (idp = hostp->oldsaved; idp; idp = idp->next)
		    fprintf(stderr, "\t%s %s\n", hostp->servername, idp->id);
	}
}

/*********************************************************************
  function:      openmailpipe
  description:   open a one-way pipe to the mail delivery agent.
  arguments:     
    queryctl     fully-determined options (i.e. parsed, defaults invoked,
                 etc).

  return value:  open file descriptor for the pipe or -1.
  calls:         none.
 *********************************************************************/

int openmailpipe (queryctl)
struct hostrec *queryctl;
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

	execv(queryctl->mda_argv[0], queryctl->mda_argv + 1);

	/* if we got here, an error occurred */
	perror("fetchmail: openmailpipe: exec");
	_exit(PS_SYNTAX);

    }

    /* in the parent process space */
    close(pipefd[0]);  /* close the 'read' end of the pipe */
    return(pipefd[1]);
}

/*********************************************************************
  function:      closemailpipe
  description:   close pipe to the mail delivery agent.
  arguments:     
    queryctl     fully-determined options record
    fd           pipe descriptor.

  return value:  0 if success, else -1.
  calls:         none.
  globals:       none.
 *********************************************************************/

int closemailpipe (fd)
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
