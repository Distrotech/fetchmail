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

#ifdef HAVE_PROTOTYPES
/* prototypes for internal functions */
int showoptions (struct optrec *options);
int parseMDAargs (struct optrec *options);
int showversioninfo (void);
#endif

/* Controls the detail of status/progress messages written to stderr */
int outlevel;      /* see the O_.* constants in popclient.h */

/* args for the MDA, parsed out in the usual fashion by parseMDAargs() */
#ifdef MDA_ARGS
char *mda_argv [MDA_ARGCOUNT + 2];
#else
char *mda_argv [2];
#endif


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

main (argc,argv)
int argc;
char **argv;
{ 
  int mboxfd;
  struct optrec cmd_opts, def_opts, merged_opts;
  int popstatus;
  int parsestatus;
  char *servername; 

  parsestatus = parsecmdline(argc,argv,&cmd_opts);
  if (parsestatus >= 0) {
    setoutlevel(&cmd_opts);
    if (!cmd_opts.versioninfo)
      if (setdefaults(&def_opts) == 0) {
        if (prc_parse_file(prc_getpathname(&cmd_opts,&def_opts)) == 0) {
          while ((servername = getnextserver(argc, argv, &parsestatus)) 
                 != (char *) 0) {
            if (outlevel != O_SILENT) 
              fprintf(stderr, "querying %s\n", servername);
            else
              ;
            prc_mergeoptions(servername, &cmd_opts, &def_opts, &merged_opts);
            parseMDAargs(&merged_opts);
	    switch (merged_opts.whichpop) {
              case P_POP2:
                popstatus = doPOP2(servername, &merged_opts);
                break;
              case P_POP3:
              case P_APOP:
                popstatus = doPOP3(servername, &merged_opts);
                break;
              default:
                fprintf(stderr,"unsupported protocol selected.\n");
            }
          }
        }
	else
          popstatus = PS_SYNTAX;
      } 
      else
        popstatus = PS_UNDEFINED;
    else
      showversioninfo();
  }
  else
    popstatus = PS_SYNTAX;

  exit(popstatus);
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
  printf("popclient release %s\n",RELEASE_TAG);
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
                 be appended.  Do NOT call when options->foldertype
                 is OF_SYSMBOX.

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

  if (options->foldertype == OF_STDOUT)
    return(1);
  else    /* options->foldertype == OF_USERMBOX */
    if ((fd = open(options->userfolder,O_CREAT|O_WRONLY|O_APPEND,0600)) >= 0) {
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

    execv(MDA_PATH,mda_argv);

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
  description:   parse the argument string given in MDA_ARGS into
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

  /* first put the MDA alias in as argv[0] */
  mda_argv[0] = MDA_ALIAS;
  
#ifdef MDA_ARGS

  /* make a writeable copy of MDA_ARGS */
  argp = strcpy((char *) malloc(strlen(MDA_ARGS)+1), MDA_ARGS);
  
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

#else 

  mda_argv[1] = (char *) 0;

#endif

}
