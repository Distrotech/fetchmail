/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       options.c
  project:      fetchmail
  programmer:   Carl Harris, ceharris@mal.com
  description:	command-line option processing

 ***********************************************************************/

#include <config.h>
#include <stdio.h>

#include <pwd.h>
#include "getopt.h"
#include "fetchmail.h"

#define LA_VERSION	1 
#define LA_ALL          2
#define LA_KILL		3
#define	LA_KEEP		4 
#define LA_VERBOSE	5 
#define LA_SILENT	6 
#define LA_STDOUT	7
#define LA_FLUSH        8
#define LA_PROTOCOL	9
#define LA_DAEMON	10
#define LA_RCFILE	11
#define LA_USERNAME	12
#define LA_REMOTEFILE	13
#define LA_PORT		14
#define LA_SMTPHOST	15
#define LA_MDA		16
#define LA_LOGFILE	17
#define LA_QUIT		18
#define LA_NOREWRITE	19
#define LA_HELP		20
#define LA_YYDEBUG	21

static char *shortoptions = "P:p:VaKkvS:m:sFd:f:u:r:L:qN?";
static struct option longoptions[] = {
  {"version",   no_argument,       (int *) 0, LA_VERSION    },
  {"all",	no_argument,       (int *) 0, LA_ALL        },
  {"kill",	no_argument,	   (int *) 0, LA_KILL       },
  {"keep",      no_argument,       (int *) 0, LA_KEEP       },
  {"verbose",   no_argument,       (int *) 0, LA_VERBOSE    },
  {"silent",    no_argument,       (int *) 0, LA_SILENT     },
  {"flush",	no_argument,	   (int *) 0, LA_FLUSH      },
  {"protocol",	required_argument, (int *) 0, LA_PROTOCOL   },
  {"proto",	required_argument, (int *) 0, LA_PROTOCOL   },
  {"daemon",	required_argument, (int *) 0, LA_DAEMON     },
  {"fetchmailrc",required_argument,(int *) 0, LA_RCFILE     },
  {"user",	required_argument, (int *) 0, LA_USERNAME   },
  {"username",  required_argument, (int *) 0, LA_USERNAME   },
  {"remote",    required_argument, (int *) 0, LA_REMOTEFILE },
  {"port",	required_argument, (int *) 0, LA_PORT       },
  {"smtphost",	required_argument, (int *) 0, LA_SMTPHOST   },
  {"mda",	required_argument, (int *) 0, LA_MDA        },
  {"logfile",	required_argument, (int *) 0, LA_LOGFILE    },
  {"quit",	no_argument,	   (int *) 0, LA_QUIT       },
  {"norewrite",	no_argument,	   (int *) 0, LA_NOREWRITE  },
  {"help",	no_argument,	   (int *) 0, LA_HELP       },
  {"yydebug",	no_argument,	   (int *) 0, LA_YYDEBUG    },
  {(char *) 0,  no_argument,       (int *) 0, 0             }
};


/*********************************************************************
  function:      parsecmdline
  description:   parse/validate the command line options.
  arguments:
    argc         argument count.
    argv         argument strings.
    queryctl     pointer to a struct hostrec to receive the parsed 
                 options.

  return value:  if positive, argv index of last parsed option + 1
		 (presumes one or more server names follows).
		 if zero, the command line switches are such that
		 no server names are required (e.g. --version).
		 if negative, the command line is has one or more
	   	 syntax errors.
  calls:         none.  
  globals:       writes outlevel, versioninfo, yydebug, logfile, 
		 poll_interval, quitmode, rcfile
 *********************************************************************/

int parsecmdline (argc,argv,queryctl)
int argc;
char **argv;
struct hostrec *queryctl;
{
  int c,i;
  int fflag = 0;     /* TRUE when -o or -c has been specified */
  int errflag = 0;   /* TRUE when a syntax error is detected */
  int option_index;
  int got_kill = 0;  /* TRUE when --kill is specified */

  extern int optind, opterr;     /* defined in getopt(2) */
  extern char *optarg;          /* defined in getopt(2) */

  memset(queryctl, '\0', sizeof(struct hostrec));    /* start clean */

  while (!errflag && 
         (c = getopt_long(argc,argv,shortoptions,
                          longoptions,&option_index)) != -1) {

    switch (c) {
      case 'V':
      case LA_VERSION:
        versioninfo = !0;
        break;
      case 'a':
      case LA_ALL:
        queryctl->fetchall = !0;
        break;
      case 'K':
      case LA_KILL:
        queryctl->keep = 0;
        got_kill = 1;
        break;
      case 'k':
      case LA_KEEP:
        queryctl->keep = !0;
        got_kill = 0;
        break;
      case 'v':
      case LA_VERBOSE:
        outlevel = O_VERBOSE;
        break;
      case 's':
      case LA_SILENT:
        outlevel = O_SILENT;
        break;
      case 'F':
      case LA_FLUSH:
        queryctl->flush = !0;
        break;
      case 'p':
      case LA_PROTOCOL:
        /* XXX -- should probably use a table lookup here */
        if (strcasecmp(optarg,"pop2") == 0)
          queryctl->protocol = P_POP2;
        else if (strcasecmp(optarg,"pop3") == 0)
          queryctl->protocol = P_POP3;
        else if (strcasecmp(optarg,"imap") == 0)
          queryctl->protocol = P_IMAP;
        else if (strcasecmp(optarg,"apop") == 0)
          queryctl->protocol = P_APOP;
        else if (strcasecmp(optarg,"rpop") == 0)
          queryctl->protocol = P_RPOP;
        else {
          fprintf(stderr,"Invalid protocol '%s'\n specified.\n", optarg);
          errflag++;
        }
        break;
      case 'd':
      case LA_DAEMON:
	poll_interval = atoi(optarg);
        break;
      case 'f':
      case LA_RCFILE:
        rcfile = (char *) xmalloc(strlen(optarg)+1);
        strcpy(rcfile,optarg);
        break;
      case 'u':
      case LA_USERNAME:
        strncpy(queryctl->remotename,optarg,sizeof(queryctl->remotename)-1);
        break;
      case 'r':
      case LA_REMOTEFILE:
        strncpy(queryctl->mailbox,optarg,sizeof(queryctl->mailbox)-1);
        break;
      case 'm':
      case LA_MDA:
        strncpy(queryctl->mda,optarg,sizeof(queryctl->mda));
        break;
      case 'P':
      case LA_PORT:
	queryctl->port = atoi(optarg);
	break;
      case 'S':
      case LA_SMTPHOST:
        if (fflag) 
          errflag++;
        else {
          fflag++;
          strncpy(queryctl->smtphost,optarg,sizeof(queryctl->smtphost)-1);
        }
	break;
      case 'L':
      case LA_LOGFILE:
        logfile = optarg;
        break;
      case 'q':
      case LA_QUIT:
        quitmode = 1;
        break;
      case 'N':
      case LA_NOREWRITE:
	queryctl->norewrite = 1;
	break;
      case LA_YYDEBUG:
	yydebug = 1;
        break;
      case '?':
      case LA_HELP:
      default:
        errflag++;
    }
  }

  if (errflag) {
    /* squawk if syntax errors were detected */
    fputs("usage:  fetchmail [options] [server ...]\n", stderr);
    fputs("  Options are as follows:\n",stderr);
    fputs("  -?, --help        display this option help\n", stderr);
    fputs("  -p, --protocol    specify pop2, pop3, imap, apop\n", stderr);
    fputs("  -V, --version     display version info\n", stderr);
    fputs("  -a, --all         retrieve old and new messages\n", stderr);
    fputs("  -F, --flush       delete old messages from server\n", stderr);
    fputs("  -K, --kill        delete new messages after retrieval\n", stderr);
    fputs("  -k, --keep        save new messages after retrieval\n", stderr);
    fputs("  -S, --smtphost    set SMTP forwarding host\n", stderr);
    fputs("  -q, --quit        kill daemon process\n", stderr);
    fputs("  -s, --silent      work silently\n", stderr);
    fputs("  -v, --verbose     work noisily (diagnostic output)\n", stderr);
    fputs("  -d, --daemon      run as a daemon once per n seconds\n", stderr);
    fputs("  -f, --fetchmailrc specify alternate run control file\n", stderr);
    fputs("  -u, --username    specify users's login on server\n", stderr);
    fputs("  -r, --remote      specify remote folder name\n", stderr);
    fputs("  -L, --logfile     specify logfile name\n", stderr);
    return(-1);
  }

  return(optind);
}

