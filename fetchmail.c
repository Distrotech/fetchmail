/* Copyright 1993-95 by Carl Harris, Jr.
 * All rights reserved
 *
 * Distribute freely, except: don't remove my name from the source or
 * documentation (don't take credit for my work), mark your changes (don't
 * get me blamed for your possible bugs), don't alter or remove this
 * notice.  May be sold if buildable source is provided to buyer.  No
 * warrantee of any kind, express or implied, is included with this
 * software; use at your own risk, responsibility for damages (if any) to
 * anyone resulting from the use of this software rests entirely with the
 * user.
 *
 * Send bug reports, bug fixes, enhancements, requests, flames, etc., and
 * I'll try to keep a version up to date.  I can be reached as follows:
 * Carl Harris <ceharris@mal.com>
 */

/***********************************************************************
  module:       popclient.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:	main driver module for popclient

  $Log: fetchmail.c,v $
  Revision 1.3  1996/06/27 19:22:32  esr
  Sent to ceharris.

  Revision 1.2  1996/06/26 19:08:59  esr
  This is what I sent Harris.

  Revision 1.1  1996/06/24 18:32:00  esr
  Initial revision

  Revision 1.7  1995/09/07 22:37:34  ceharris
  Preparation for 3.0b4 release.

  Revision 1.6  1995/08/14 18:36:43  ceharris
  Patches to support POP3's LAST command.
  Final revisions for beta3 release.

  Revision 1.5  1995/08/10 00:32:39  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.4  1995/08/09 01:32:56  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.3  1995/08/08 01:01:25  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

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

#include "popclient.h"

/* release info */
#define         RELEASE_TAG	"3.0b6"

struct hostrec {
  char *servername;
  struct optrec options;
  struct hostrec *next;
};

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int showoptions (struct optrec *options);
int parseMDAargs (struct optrec *options);
int showversioninfo (void);
int dump_options (struct optrec *options);
int query_host(char *servername, struct optrec *options);
#endif

/* Controls the detail of status/progress messages written to stderr */
int outlevel;		/* see the O_.* constants in popclient.h */

/* Daemon-mode control */
int poll_interval;	/* polling interval for daemon mode */
char *logfile;		/* logfile to ship progress reports to */ 
int quitmode;		/* if -quit was set */

/* args for the MDA, parsed out in the usual fashion by parseMDAargs() */
char *mda_argv [32];

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

main (argc,argv)
int argc;
char **argv;
{ 
  int mboxfd;
  struct optrec cmd_opts, def_opts, merged_opts;
  int popstatus;
  int parsestatus;
  char *servername; 
  struct hostrec *hostp, *hostlist = (struct hostrec *)NULL;
  FILE	*tmpfp;
  pid_t pid;

  if ((parsestatus = parsecmdline(argc,argv,&cmd_opts)) < 0)
    exit(PS_SYNTAX);

  setoutlevel(&cmd_opts);
  if (cmd_opts.versioninfo)
    showversioninfo();

  if (setdefaults(&def_opts) != 0)
    exit(PS_UNDEFINED);

  if (prc_parse_file(prc_getpathname(&cmd_opts,&def_opts)) != 0)
    exit(PS_SYNTAX);

  if (optind >= argc)
    append_server_names(&argc, argv);

  /* build in-core data list on all hosts */
  while ((servername = getnextserver(argc, argv, &parsestatus)) != (char *)0) {
    if (strcmp(servername, "defaults") == 0)
      continue;

    prc_mergeoptions(servername, &cmd_opts, &def_opts, &merged_opts);
    parseMDAargs(&merged_opts);

    hostp = (struct hostrec *)xmalloc(sizeof(struct hostrec));
    hostp->servername = strdup(servername);
    memcpy(&hostp->options, &merged_opts, sizeof(struct optrec));

    hostp->next = hostlist;
    hostlist = hostp;
  }

  /* perhaps we just want to check options? */
  if (cmd_opts.versioninfo) {
    printf("Taking options from command line and %s\n", prc_pathname);
    for (hostp = hostlist; hostp; hostp = hostp->next) {
      printf("Options for host %s:\n", hostp->servername);
      dump_options(&hostp->options);
    }
    if (hostlist == NULL)
	(void) printf("No mailservers set up -- perhaps %s is missing?\n",
		      prc_pathname);
    exit(0);
  }
  else if (hostlist == NULL) {
    (void) fputs("popclient: no mailservers have been specified.\n", stderr);
    exit(PS_SYNTAX);
  }

  /* beyond here we don't want more than one popclient running per user */
  umask(0077);
  if ((lockfile = (char *) malloc( strlen(getenv("HOME")) + strlen("/.lockfetch-") + HOSTLEN)) == NULL) {
    fprintf(stderr,"popclient: cannot allocate memory for .lockfetch, exiting.\n");
    exit(PS_EXCLUDE);
  }
  strcpy(lockfile, getenv("HOME"));
  strcat(lockfile,"/.lockfetch-");
  gethostname(lockfile+strlen(lockfile),HOSTLEN);

  /* check the lock, maybe remove it */
  if (!quitmode)
    {
      /* check the lock */
      if ( (tmpfp = fopen(lockfile, "r")) != NULL ) {
	fscanf(tmpfp,"%d",&pid);
	fprintf(stderr,"Another session appears to be running at pid %d.\nIf you are sure that this is incorrect, remove %s file.\n",pid,lockfile);
	fclose(tmpfp);
	return(PS_EXCLUDE);
      }

      /* if not locked, assert a lock */
      else if ( (tmpfp = fopen(lockfile,"w")) != NULL ) {
	signal(SIGABRT, termhook);
	signal(SIGINT, termhook);
	signal(SIGTERM, termhook);
	signal(SIGALRM, termhook);
	signal(SIGHUP, termhook);
	signal(SIGPIPE, termhook);
	signal(SIGQUIT, termhook);
	fprintf(tmpfp,"%d",getpid());
	fclose(tmpfp);
      }
    }
  else
    {
      FILE* fp;

      if ( (fp = fopen(lockfile, "r")) == NULL ) {
	fprintf(stderr,"popclient: no other popclient is running\n");
	return(PS_EXCLUDE);
      }
  
      fscanf(fp,"%d",&pid);
      fprintf(stderr,"popclient: killing popclient at PID %d\n",pid);
      if ( kill(pid,SIGKILL) < 0 )
	fprintf(stderr,"popclient: error killing the process %d\n.",pid);
      else
	fprintf(stderr,"popclient: popclient at %d is dead.\n", pid);
  
      fclose(fp);
      remove(lockfile);
      exit(0);
    }

  /*
   * Maybe time to go to demon mode...
   */
  if (poll_interval)
    daemonize(logfile, termhook);

  /*
   * Query all hosts. If there's only one, the error return will
   * reflect the status of that transaction.
   */
  do {
      for (hostp = hostlist; hostp; hostp = hostp->next) {
	  popstatus = query_host(hostp->servername, &hostp->options);
      }

      sleep(poll_interval);
  } while
      (poll_interval);

  termhook();
  exit(popstatus);
}

void termhook()
{
    unlink(lockfile);
}

int query_host(servername, options)
/* perform fetch transaction with single host */
char *servername;
struct optrec *options;
{
  if (outlevel != O_SILENT)
    fprintf(stderr, "querying %s\n", servername);
  switch (options->whichpop) {
  case P_POP2:
    return(doPOP2(servername, options));
    break;
  case P_POP3:
  case P_APOP:
    return(doPOP3(servername, options));
    break;
  default:
    fprintf(stderr,"unsupported protocol selected.\n");
    return(PS_PROTOCOL);
  }
}
 
/*********************************************************************
  function:      showversioninfo
  description:   display program release and compiler info
  arguments:     none.
  return value:  none.
  calls:         none.
  globals:       none.
 *********************************************************************/

int showversioninfo()
{
  printf("This is popclient release %s\n",RELEASE_TAG);
}

/*********************************************************************
  function:      dump_options
  description:   display program options in English
  arguments:
    options      merged options

  return value:  none.
  calls:         none.
  globals:       none.
*********************************************************************/

int dump_options (options)
struct optrec *options;
{
  if (!options->loginid[0])
    printf("  No password set\n");
  else
    printf("  Username = '%s'\n", options->loginid);
  printf("  Password = '%s'\n", options->password);

  printf("  Protocol is ");
  switch (options->whichpop)
  {
  case P_POP2: printf("POP2\n"); break;
  case P_POP3: printf("POP3\n"); break;
  case P_IMAP: printf("IMAP\n"); break;
  case P_APOP: printf("APOP\n"); break;
  case P_RPOP: printf("RPOP\n"); break;
  default: printf("unknown?!?\n"); break;
  }

  printf("  Fetched messages will%s be kept on the server (--keep %s).\n",
	 options->keep ? "" : " not",
	 options->keep ? "on" : "off");
  printf("  %s messages will be retrieved (--all %s).\n",
	 options->fetchall ? "All" : "Only new",
         options->fetchall ? "on" : "off");
  printf("  Old messages will%s be flushed before message retrieval (--flush %s).\n",
	 options->flush ? "" : " not",
         options->flush ? "on" : "off");

  switch(options->output)
  {
  case TO_FOLDER:
    printf("  Messages will be appended to '%s'\n", options->userfolder);
    break;
  case TO_MDA:
    printf("  Messages will be delivered with %s\n", options->mda);
    break;
  case TO_STDOUT:
    printf("  Messages will be dumped to standard output\n");
  default:
    printf("  Message destination unknown?!?\n");
  }
  if (options->verbose)
    {
      if (options->output != TO_FOLDER)
	printf("  (Mail folder would have been '%s')\n", options->userfolder);
      if (options->output != TO_MDA)
	printf("  (MDA would have been '%s')\n", options->mda);
    }

  if (options->limit == 0)
    printf("  No limit on retrieved message length.\n");
  else
    printf("  Text retrieved per message will be at most %d bytes.\n",
	   options->limit);
}

/******************************************************************
  function:	setoutlevel
  description:	set output verbosity level.
  arguments:
    options	command-line options.

  ret. value:	none.
  globals:	writes outlevel.
  calls:	none.
 *****************************************************************/

int setoutlevel (options)
struct optrec *options;
{
  if (options->verbose) 
    outlevel = O_VERBOSE;
  else if (options->silent)
    outlevel = O_SILENT;
  else
    outlevel = O_NORMAL;
}



/*********************************************************************
  function:      openuserfolder
  description:   open the file to which the retrieved messages will
                 be appended.  Write-lock the folder if possible.

  arguments:     
    options      fully-determined options (i.e. parsed, defaults invoked,
                 etc).

  return value:  file descriptor for the open file, else -1.
  calls:         none.
  globals:       none.
 *********************************************************************/

int openuserfolder (options)
struct optrec *options;
{
  int fd;

  if (options->output == TO_STDOUT)
    return(1);
  else    /* options->output == TO_FOLDER */
    if ((fd = open(options->userfolder,O_CREAT|O_WRONLY|O_APPEND,0600)) >= 0) {
#ifdef HAVE_FLOCK
      if (flock(fd, LOCK_EX) == -1)
	{
	  close(fd);
	  fd = -1;
	}
#endif /* HAVE_FLOCK */
      return(fd);
    }
    else {
      perror("popclient: openuserfolder: open()");
      return(-1);
    }
  
}



/*********************************************************************
  function:      openmailpipe
  description:   open a one-way pipe to the mail delivery agent.
  arguments:     
    options      fully-determined options (i.e. parsed, defaults invoked,
                 etc).

  return value:  open file descriptor for the pipe or -1.
  calls:         none.
  globals:       reads mda_argv.
 *********************************************************************/

int openmailpipe (options)
struct optrec *options;
{
  int pipefd [2];
  int childpid;
  char binmailargs [80];

  if (pipe(pipefd) < 0) {
    perror("popclient: openmailpipe: pipe");
    return(-1);
  }
  if ((childpid = fork()) < 0) {
    perror("popclient: openmailpipe: fork");
    return(-1);
  }
  else if (childpid == 0) {

    /* in child process space */
    close(pipefd[1]);  /* close the 'write' end of the pipe */
    close(0);          /* get rid of inherited stdin */
    if (dup(pipefd[0]) != 0) {
      fputs("popclient: openmailpipe: dup() failed\n",stderr);
      exit(1);
    }

    execv(options->mda,mda_argv);

    /* if we got here, an error occurred */
    perror("popclient: openmailpipe: exec");
    return(-1);

  }

  /* in the parent process space */
  close(pipefd[0]);  /* close the 'read' end of the pipe */
  return(pipefd[1]);
}



/*********************************************************************
  function:      closeuserfolder
  description:   close the user-specified mail folder.
  arguments:     
    fd           mail folder descriptor.

  return value:  zero if success else -1.
  calls:         none.
  globals:       none.
 *********************************************************************/

int closeuserfolder(fd)
int fd;
{
  int err;

  if (fd != 1) {   /* not stdout */
    err = close(fd);
  }   
  else
    err = 0;
  
  if (err)
    perror("popclient: closeuserfolder: close");

  return(err);
}



/*********************************************************************
  function:      closemailpipe
  description:   close pipe to the mail delivery agent.
  arguments:     
    options      fully-determined options record
    fd           pipe descriptor.

  return value:  0 if success, else -1.
  calls:         none.
  globals:       none.
 *********************************************************************/

int closemailpipe (fd)
int fd;
{
  int err;
  int childpid;

  err = close(fd);
#if defined(STDC_HEADERS)
  childpid = wait(NULL);
#else
  childpid = wait((int *) 0);
#endif
  if (err)
    perror("popclient: closemailpipe: close");

  return(err);
}



/*********************************************************************
  function:      parseMDAargs
  description:   parse the argument string given in agent option into
                 a regular *argv[] array.
  arguments:
    options      fully-determined options record pointer.

  return value:  none.
  calls:         none.
  globals:       writes mda_argv.
 *********************************************************************/

int parseMDAargs (options)
struct optrec *options;
{
  int argi;
  char *argp;

  /* first put the last segment of the MDA pathname in argv[0] */
  argp = strrchr(options->mda, '/');
  mda_argv[0] = argp ? (argp + 1) : options->mda;
  
  argp = options->mda;
  while (*argp != '\0' && isspace(*argp))	/* skip null first arg */
    argp++;					

  /* now punch nulls into the delimiting whitespace in the args */
  for (argi = 1;  
       *argp != '\0';
       argi++) {

    mda_argv[argi] = argp;     /* store pointer to this argument */

    /* find end of this argument */
    while (!(*argp == '\0' || isspace(*argp)))
      argp++;

    /* punch in a null terminator */
    if (*argp != '\0')
      *(argp++) = '\0';  
 
    /* check for macros */
    if (strcmp(mda_argv[argi],"$u") == 0)
      mda_argv[argi] = 
        strcpy((char *) malloc(strlen(options->loginid)+1),options->loginid);
    else
      ;  /* no macros to expand */

  }
  mda_argv[argi] = (char *) 0;

}

/*********************************************************************
  function:      
  description:   hack message headers so replies will work properly

  arguments:
    after        where to put the hacked header
    before       header to hack
    host         name of the pop header

  return value:  none.
  calls:         none.
  globals:       writes mda_argv.
 *********************************************************************/

void reply_hack(buf, host)
/* hack local mail IDs -- code by Eric S. Raymond 20 Jun 1996 */
char *buf;
const char *host;
{
  const char *from;
  int state = 0;
  char mycopy[POPBUFSIZE];

  if (strncmp("From: ", buf, 6)
      && strncmp("To: ", buf, 4)
      && strncmp("Reply-", buf, 6)
      && strncmp("Cc: ", buf, 4)
      && strncmp("Bcc: ", buf, 5)) {
    return;
  }

  strcpy(mycopy, buf);
  for (from = mycopy; *from; from++)
  {
    switch (state)
      {
      case 0:   /* before header colon */
        if (*from == ':')
          state = 1;
        break;

      case 1:   /* we've seen the colon, we're looking for addresses */
        if (*from == '"')
          state = 2;
        else if (*from == '(')
          state = 3;    
        else if (*from == '<' || isalnum(*from))
          state = 4;
        break;

      case 2:   /* we're in a quoted human name, copy and ignore */
        if (*from == '"')
          state = 1;
        break;

      case 3:   /* we're in a parenthesized human name, copy and ignore */
        if (*from == ')')
          state = 1;
        break;

      case 4:   /* the real work gets done here */
        /*
         * We're in something that might be an address part,
         * either a bare unquoted/unparenthesized text or text
         * enclosed in <> as per RFC822.
         */
        /* if the address part contains an @, don't mess with it */
        if (*from == '@')
          state = 5;

        /* If the address token is not properly terminated, ignore it. */
        else if (*from == ' ' || *from == '\t')
          state = 1;

        /*
         * On proper termination with no @, insert hostname.
         * Case '>' catches <>-enclosed mail IDs.  Case ',' catches
         * comma-separated bare IDs.  Cases \r and \n catch the case
         * of a single ID alone on the line.
         */
        else if (strchr(">,\r\n", *from))
        {
          strcpy(buf, "@");
          strcat(buf, host);
          buf += strlen(buf);
          state = 1;
        }

        /* everything else, including alphanumerics, just passes through */
        break;

      case 5:   /* we're in a remote mail ID, no need to append hostname */
        if (*from == '>' || *from == ',' || isspace(*from))
          state = 1;
        break;
      }

    /* all characters from the old buffer get copied to the new one */
    *buf++ = *from;
  }
  *buf++ = '\0';
}

