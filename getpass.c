/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       getpass.c
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
  description: 	getpass() replacement which allows for long passwords.

 ***********************************************************************/

#include <config.h>
#include <stdio.h>
#include <signal.h>

extern int optind;

#define INPUT_BUF_SIZE	MAX_PASSWORD_LENGTH

#if defined(HAVE_TERMIOS_H) && defined(HAVE_TCSETATTR)
#  include <termios.h>
#else
#if defined(HAVE_TERMIO_H)
#  include <sys/ioctl.h>
#  include <termio.h>
#else
#if defined(HAVE_SGTTY_H)
#  include <sgtty.h>
#endif
#endif
#endif

static int ttyfd;

#if defined(HAVE_TCSETATTR)
  static struct termios termb;
  static tcflag_t flags;
#else
#if defined(HAVE_TERMIO_H)
  static struct termio termb;
  static unsigned short flags;
#else
#if defined(HAVE_STTY)
  static struct sgttyb ttyb;
  static int flags;
#endif
#endif
#endif

void save_tty_state();
void disable_tty_echo();
void restore_tty_state();

char *
getpassword(prompt)
char *prompt;
{

#if !(defined(HAVE_TCSETATTR) || defined(HAVE_TERMIO_H) || defined(HAVE_STTY))

#if defined(HAVE_GETPASS) 
  char *getpass();
  return getpass(prompt);
#else
  fputs("ERROR: no support for getpassword() routine\n",stderr);
  exit(1);
#endif

#endif /* !(defined(HAVE_TCSETATTR) || ... */

  register char *p;
  register c;
  FILE *fi;
  static char pbuf[INPUT_BUF_SIZE];
  RETSIGTYPE (*sig)();
  RETSIGTYPE sigint_handler();


  /* get the file descriptor for the input device */
  if ((fi = fdopen(open("/dev/tty", 2), "r")) == NULL)
    fi = stdin;
  else
    setbuf(fi, (char *)NULL);

  /* store descriptor for the tty */
  ttyfd = fileno(fi);

  /* preserve tty state before turning off echo */
  save_tty_state();

  /* now that we have the current tty state, we can catch SIGINT and  
     exit gracefully */
  sig = signal(SIGINT, sigint_handler);

  /* turn off echo on the tty */
  disable_tty_echo();

  /* display the prompt and get the input string */
  fprintf(stderr, "%s", prompt); fflush(stderr);
  for (p=pbuf; (c = getc(fi))!='\n' && c!=EOF;) {
    if (p < &pbuf[INPUT_BUF_SIZE - 1])
      *p++ = c;
  }
  *p = '\0';

  /* write a newline so cursor won't appear to hang */
  fprintf(stderr, "\n"); fflush(stderr);

  /* restore previous state of the tty */
  restore_tty_state();

  /* restore previous state of SIGINT */
  signal(SIGINT, sig);

  if (fi != stdin)
    fclose(fi);

  return(pbuf);

}


void
save_tty_state ()
{
#if defined(HAVE_TCSETATTR)
  tcgetattr(ttyfd, &termb);
  flags = termb.c_lflag;
#else
#if defined(HAVE_TERMIO_H)
  ioctl(ttyfd, TCGETA, (char *) &termb);
  flags = termb.c_lflag;
#else  /* we HAVE_STTY */
  gtty(ttyfd, &ttyb);
  flags = ttyb.sg_flags;
#endif
#endif
}


void
disable_tty_echo() 
{
  /* turn off echo on the tty */
#if defined(HAVE_TCSETATTR)
  termb.c_lflag &= ~ECHO;
  tcsetattr(ttyfd, TCSAFLUSH, &termb);
#else
#if defined(HAVE_TERMIO_H)
  termb.c_lflag &= ~ECHO;
  ioctl(ttyfd, TCSETA, (char *) &termb);
#else  /* we HAVE_STTY */
  ttyb.sg_flags &= ~ECHO;
  stty(ttyfd, &ttyb);
#endif
#endif
}



void
restore_tty_state()
{
  /* restore previous tty echo state */
#if defined(HAVE_TCSETATTR)
  termb.c_lflag = flags;
  tcsetattr(ttyfd, TCSAFLUSH, &termb);
#else
#if defined(HAVE_TERMIO_H)
  termb.c_lflag = flags;
  ioctl(ttyfd, TCSETA, (char *) &termb);
#else  /* we HAVE_STTY */
  ttyb.sg_flags = flags;
  stty(ttyfd, &ttyb);
#endif
#endif
}


RETSIGTYPE sigint_handler ()
{
  restore_tty_state();
  fputs("\nCaught signal... bailing out.\n", stderr);
  exit(1);
}
