/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       popclient.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
		Extensively hacked and improved by esr.
  description:	main driver module for popclient

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
#define         RELEASE_TAG	"3.1"

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int showoptions (struct hostrec *queryctl);
int parseMDAargs (struct hostrec *queryctl);
int showversioninfo (void);
int dump_options (struct hostrec *queryctl);
int query_host(struct hostrec *queryctl);
#endif

/* controls the detail level of status/progress messages written to stderr */
int outlevel;    	/* see the O_.* constants above */
int yydebug;		/* enable parse debugging */

/* daemon mode control */
int poll_interval;	/* poll interval in seconds */
char *logfile;		/* log file for daemon mode */
int quitmode;		/* if --quit was set */

/* miscellaneous global controls */
char *poprcfile;	/* path name of rc file */
char *idfile;		/* path name of id file */
int linelimit;		/* limit # lines retrieved per site */
int versioninfo;	/* emit only version info */

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
static int popstatus;
static struct hostrec *hostp, *hostlist = (struct hostrec *)NULL;

main (argc,argv)
int argc;
char **argv;
{ 
  int mboxfd, st;
  struct hostrec cmd_opts, def_opts;
  int parsestatus;
  char *servername; 
  FILE	*tmpfp;
  pid_t pid;

  if (setdefaults(&def_opts) != 0)
    exit(PS_UNDEFINED);

  if ((parsestatus = parsecmdline(argc,argv,&cmd_opts)) < 0)
    exit(PS_SYNTAX);

  if (versioninfo)
    showversioninfo();

  if (prc_parse_file(poprcfile) != 0)
    exit(PS_SYNTAX);

  if (optind >= argc)
    append_server_names(&argc, argv);

  /* build in-core data list on all hosts */
  while ((servername = getnextserver(argc, argv, &parsestatus)) != (char *)0) {
    if (strcmp(servername, "defaults") == 0)
      continue;

    hostp = (struct hostrec *)xmalloc(sizeof(struct hostrec));

    prc_mergeoptions(servername, &cmd_opts, &def_opts, hostp);
    strcpy(hostp->servername, servername);
    parseMDAargs(hostp);
    hostp->lastid[0] = '\0';

    hostp->next = hostlist;
    hostlist = hostp;
  }

  /* perhaps we just want to check options? */
  if (versioninfo) {
    printf("Taking options from command line and %s\n", poprcfile);
    for (hostp = hostlist; hostp; hostp = hostp->next) {
      printf("Options for host %s:\n", hostp->servername);
      dump_params(hostp);
    }
    if (hostlist == NULL)
	(void) printf("No mailservers set up -- perhaps %s is missing?\n",
		      poprcfile);
    exit(0);
  }
  else if (hostlist == NULL) {
    (void) fputs("popclient: no mailservers have been specified.\n", stderr);
    exit(PS_SYNTAX);
  }

  /* set up to do lock protocol */
  umask(0077);
  if ((lockfile = (char *) malloc( strlen(getenv("HOME")) + strlen("/.lockfetch-") + HOSTLEN)) == NULL) {
    fprintf(stderr,"popclient: cannot allocate memory for .lockfetch, exiting.\n");
    exit(PS_EXCLUDE);
  }
  strcpy(lockfile, getenv("HOME"));
  strcat(lockfile,"/.lockfetch-");
  gethostname(lockfile+strlen(lockfile),HOSTLEN);

  /* perhaps user asked us to remove a lock */
  if (quitmode)
    {
      FILE* fp;

      if ( (fp = fopen(lockfile, "r")) == NULL ) {
	fprintf(stderr,"popclient: no other popclient is running\n");
	return(PS_EXCLUDE);
      }
  
      fscanf(fp,"%d",&pid);
      fprintf(stderr,"popclient: killing popclient at PID %d\n",pid);
      if ( kill(pid,SIGTERM) < 0 )
	fprintf(stderr,"popclient: error killing the process %d.\n",pid);
      else
	fprintf(stderr,"popclient: popclient at %d is dead.\n", pid);
  
      fclose(fp);
      remove(lockfile);
      exit(0);
    }


  /* beyond here we don't want more than one popclient running per user */
  if ( (tmpfp = fopen(lockfile, "r")) != NULL ) {
    fscanf(tmpfp,"%d",&pid);
    fprintf(stderr,"Another session appears to be running at pid %d.\nIf you are sure that this is incorrect, remove %s file.\n",pid,lockfile);
    fclose(tmpfp);
    return(PS_EXCLUDE);
  }

  /* let's get stored message IDs from previous transactions */
  if ((st = prc_filecheck(idfile)) != 0) {
      return (st);
  } else if ((tmpfp = fopen(idfile, "r")) != (FILE *)NULL) {
     char buf[POPBUFSIZE+1], host[HOSTLEN+1], id[IDLEN+1];

     while (fgets(buf, POPBUFSIZE, tmpfp) != (char *)NULL) {
       if ((st = sscanf(buf, "%s %s\n", host, id)) == 2) {
         for (hostp = hostlist; hostp; hostp = hostp->next) {
           if (strcmp(host, hostp->servername) == 0)
	       strcpy(hostp->lastid, id);
         }
       }
     }
     fclose(tmpfp);
  }

  /*
   * Maybe time to go to demon mode...
   */
  if (poll_interval)
    daemonize(logfile, termhook);

  /* if not locked, assert a lock */
  signal(SIGABRT, termhook);
  signal(SIGINT, termhook);
  signal(SIGTERM, termhook);
  signal(SIGALRM, termhook);
  signal(SIGHUP, termhook);
  signal(SIGPIPE, termhook);
  signal(SIGQUIT, termhook);
  if ( (tmpfp = fopen(lockfile,"w")) != NULL ) {
      fprintf(tmpfp,"%d",getpid());
      fclose(tmpfp);
  }

  /*
   * Query all hosts. If there's only one, the error return will
   * reflect the status of that transaction.
   */
  do {
      for (hostp = hostlist; hostp; hostp = hostp->next) {
	  popstatus = query_host(hostp);
      }

      sleep(poll_interval);
  } while
      (poll_interval);

  if (outlevel == O_VERBOSE)
      fprintf(stderr, "normal termination\n");

  termhook(0);
  exit(popstatus);
}

void termhook(int sig)
{
  FILE *tmpfp;
  int idcount = 0;

  if (sig != 0)
      fprintf(stderr, "terminated with signal %d\n", sig);

  for (hostp = hostlist; hostp; hostp = hostp->next) {
    if (hostp->lastid[0])
	idcount++;
  }

  /* write updated last-seen IDs */
  if (!idcount)
     unlink(idfile);
  else if ((tmpfp = fopen(idfile, "w")) != (FILE *)NULL) {
    for (hostp = hostlist; hostp; hostp = hostp->next) {
      if (hostp->lastid[0])
        fprintf(tmpfp, "%s %s\n", hostp->servername, hostp->lastid);
    }
    fclose(tmpfp);
  }

  unlink(lockfile);
  exit(popstatus);
}

int query_host(queryctl)
/* perform fetch transaction with single host */
struct hostrec *queryctl;
{
  if (outlevel != O_SILENT)
  {
    time_t now;

    time(&now);
    fprintf(stderr, "popclient: querying %s at %s",
	    queryctl->servername, ctime(&now));
  }
  switch (queryctl->protocol) {
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
    fprintf(stderr,"popclient: unsupported protocol selected.\n");
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
  function:      dump_params
  description:   display program options in English
  arguments:
    queryctl      merged options

  return value:  none.
  calls:         none.
  globals:       linelimit, outlimit.
*********************************************************************/

int dump_params (queryctl)
struct hostrec *queryctl;
{
  char *cp;

  printf("  Username = '%s'\n", queryctl->remotename);
  printf("  Password = '%s'\n", queryctl->password);

  printf("  Protocol is ");
  switch (queryctl->protocol)
  {
  case P_POP2: printf("POP2\n"); break;
  case P_POP3: printf("POP3\n"); break;
  case P_IMAP: printf("IMAP\n"); break;
  case P_APOP: printf("APOP\n"); break;
  case P_RPOP: printf("RPOP\n"); break;
  default: printf("unknown?!?\n"); break;
  }

  printf("  Fetched messages will%s be kept on the server (--keep %s).\n",
	 queryctl->keep ? "" : " not",
	 queryctl->keep ? "on" : "off");
  printf("  %s messages will be retrieved (--all %s).\n",
	 queryctl->fetchall ? "All" : "Only new",
         queryctl->fetchall ? "on" : "off");
  printf("  Old messages will%s be flushed before message retrieval (--flush %s).\n",
	 queryctl->flush ? "" : " not",
         queryctl->flush ? "on" : "off");

  switch(queryctl->output)
  {
  case TO_FOLDER:
    printf("  Messages will be appended to '%s'\n", queryctl->userfolder);
    break;
  case TO_MDA:
    printf("  Messages will be delivered with");
    for (cp = queryctl->mda; *cp; cp += strlen(cp) + 1) {
	printf(" %s", cp);
    }
    putchar('\n');
    break;
  case TO_STDOUT:
    printf("  Messages will be dumped to standard output\n");
  default:
    printf("  Message destination unknown?!?\n");
  }
  if (outlevel == O_VERBOSE)
    {
      if (queryctl->output != TO_FOLDER)
	printf("  (Mail folder would have been '%s')\n", queryctl->userfolder);
      if (queryctl->output != TO_MDA)
      {
	printf("  (MDA would have been");
	for (cp = queryctl->mda; *cp; cp += strlen(cp) + 1) {
	  printf(" %s", cp);
	}
	printf(")\n");
      }
    }

  if (linelimit == 0)
    printf("  No limit on retrieved message length.\n");
  else
    printf("  Text retrieved per message will be at most %d bytes.\n",
	   linelimit);
  if (queryctl->lastid[0])
    printf("  ID of last message retrieved %s\n", queryctl->lastid);
}

/*********************************************************************
  function:      openuserfolder
  description:   open the file to which the retrieved messages will
                 be appended.  Write-lock the folder if possible.

  arguments:     
    queryctl     fully-determined options (i.e. parsed, defaults invoked,
                 etc).

  return value:  file descriptor for the open file, else -1.
  calls:         none.
  globals:       none.
 *********************************************************************/

int openuserfolder (queryctl)
struct hostrec *queryctl;
{
  int fd;

  if (queryctl->output == TO_STDOUT)
    return(1);
  else    /* queryctl->output == TO_FOLDER */
    if ((fd = open(queryctl->userfolder,O_CREAT|O_WRONLY|O_APPEND,0600)) >= 0) {
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
    queryctl     fully-determined options (i.e. parsed, defaults invoked,
                 etc).

  return value:  open file descriptor for the pipe or -1.
  calls:         none.
  globals:       reads mda_argv.
 *********************************************************************/

int openmailpipe (queryctl)
struct hostrec *queryctl;
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

    execv(queryctl->mda, mda_argv+1);

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
    queryctl     fully-determined options record
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

  if (outlevel == O_VERBOSE)
      fprintf(stderr, "about to close pipe %d\n", fd);

  err = close(fd);
#if defined(STDC_HEADERS)
  childpid = wait(NULL);
#else
  childpid = wait((int *) 0);
#endif
  if (err)
    perror("popclient: closemailpipe: close");

  if (outlevel == O_VERBOSE)
    fprintf(stderr, "closed pipe %d\n", fd);
  
  return(err);
}



/*********************************************************************
  function:      parseMDAargs
  description:   parse the argument string given in agent option into
                 a regular *argv[] array.
  arguments:
    queryctl     fully-determined options record pointer.

  return value:  none.
  calls:         none.
  globals:       writes mda_argv.
 *********************************************************************/

int parseMDAargs (queryctl)
struct hostrec *queryctl;
{
  int argi;
  char *argp;

  /* first put the last segment of the MDA pathname in argv[0] */
  argp = strrchr(queryctl->mda, '/');
  mda_argv[0] = argp ? (argp + 1) : queryctl->mda;
  
  argp = queryctl->mda;
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

