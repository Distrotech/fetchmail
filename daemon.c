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
  module:       daemon
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:  This module contains all of the code needed to 
	 	turn a process into a daemon for POSIX, SysV, and
		BSD systems.

  $Log: daemon.c,v $
  Revision 1.3  1996/06/27 19:22:31  esr
  Sent to ceharris.

  Revision 1.2  1996/06/26 19:08:57  esr
  This is what I sent Harris.

  Revision 1.1  1996/06/25 14:32:01  esr
  Initial revision

  Revision 1.1  1995/08/14 18:36:38  ceharris
  Patches to support POP3's LAST command.
  Final revisions for beta3 release.

 ***********************************************************************/


#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <signal.h>
#include <fcntl.h>

#if defined(HAVE_SYS_WAIT_H)
#  include <sys/wait.h>
#endif

#if defined(HAVE_UNISTD_H)
#  include <unistd.h>
#endif


#include "popclient.h"

static void (*my_termhook)(void);

/******************************************************************
  function:	sigchld_handler
  description:	Process the SIGCHLD (a.k.a SIGCLD) signal by calling
		a wait() variant to obtain the exit code of the 
		terminating process.
  arguments:	none.
  ret. value:	none (or undefined if REGSIGTYPE is int).
  globals:	none.
  calls:	none.
 *****************************************************************/

RETSIGTYPE
sigchld_handler ()
{
  pid_t pid;

#if defined(HAVE_UNION_WAIT)
  union wait status;
#else
  int status;
#endif

  if (my_termhook)
      (*my_termhook)();

#if 	defined(HAVE_WAIT3)
  while ((pid = wait3(&status, WNOHANG, (struct rusage *) 0)) > 0)
    ; /* swallow 'em up. */
#elif 	defined(HAVE_WAITPID)
  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    ; /* swallow 'em up. */
#else	/* Zooks! Nothing to do but wait(), and hope we don't block... */
  wait(&status);
#endif

}



/******************************************************************
  function:	daemonize
  description:	become a daemon process; i.e. detach from the 
		control terminal, don't reacquire a control terminal,
                become process group leader of our own process group,
                and set up to catch child process termination signals.
  arguments:
    logfile     file to direct stdout and stderr to, if non-NULL.

  ret. value:	none.
  globals:	refers to the address of sigchld_handler().
  calls:	none.
 *****************************************************************/

int
daemonize (logfile, termhook)
const char *logfile;
void (*termhook)(void);
{
  int fd;
  pid_t childpid;
  RETSIGTYPE sigchld_handler();

  /* if we are started by init (process 1) via /etc/inittab we needn't 
     bother to detach from our process group context */

  my_termhook = termhook;

  if (getppid() == 1) 
    goto nottyDetach;

  /* Ignore BSD terminal stop signals */
#ifdef 	SIGTTOU
  signal(SIGTTOU, SIG_IGN);
#endif
#ifdef	SIGTTIN
  signal(SIGTTIN, SIG_IGN);
#endif
#ifdef	SIGTSTP
  signal(SIGTSTP, SIG_IGN);
#endif

  /* In case we were not started in the background, fork and let
     the parent exit.  Guarantees that the child is not a process
     group leader */

  if ((childpid = fork()) < 0) {
    perror("fork");
    return(PS_IOERR);
  }
  else if (childpid > 0) 
    exit(0);  /* parent */

  
  /* Make ourselves the leader of a new process group with no
     controlling terminal */

#if	defined(HAVE_SETSID)		/* POSIX */
  /* POSIX makes this soooo easy to do */
  if (setsid() < 0) {
    perror("setsid");
    return(PS_IOERR);
  }
#elif	defined(SIGTSTP)		/* BSD */
  /* change process group */
  setpgrp(0, getpid());

  /* lose controlling tty */
  if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
    ioctl(fd, TIOCNOTTY, (char *) 0);
    close(fd);
  }
#else					/* SVR3 and older */
  /* change process group */
  setpgrp();
  
  /* lose controlling tty */
  signal(SIGHUP, SIG_IGN);
  if ((childpid = fork) < 0) {
    perror("fork");
    return(PS_IOERR);
  }
  else if (childpid > 0) {
    exit(0); 	/* parent */
  }
#endif

nottyDetach:

  /* Close any/all open file descriptors */
#if 	defined(HAVE_GETDTABLESIZE)
  for (fd = getdtablesize()-1;  fd >= 0;  fd--)
#elif	defined(NOFILE)
  for (fd = NOFILE-1;  fd >= 0;  fd--)
#else		/* make an educated guess */
  for (fd = 19;  fd >= 0;  fd--)
#endif
  {
    close(fd);
  }

  /* Reopen stdin descriptor on /dev/null */
  if ((fd = open("/dev/null", O_RDWR)) < 0) {   /* stdin */
    perror("open: /dev/null");
    return(PS_IOERR);
  }

  if (logfile)
    open(logfile, O_CREAT|O_WRONLY, 0777);	/* stdout */
  else
    if (dup(fd) < 0) {				/* stdout */
      perror("dup");
      return(PS_IOERR);
    }
  if (dup(fd) < 0) {				/* stderr */
    perror("dup");
    return(PS_IOERR);
  }

  /* move to root directory, so we don't prevent filesystem unmounts */
  chdir("/");

  /* set our umask to something reasonable (we hope) */
#if defined(DEF_UMASK)
  umask(DEF_UMASK);
#else
  umask(022);
#endif

  /* set up to catch child process termination signals */ 
  signal(SIGCLD, sigchld_handler); 

}
