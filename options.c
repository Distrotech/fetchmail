/* Copyright 1993-95 by Carl Harris, Jr. Copyright 1996 by Eric S. Raymond
 * All rights reserved.
 * For license terms, see the file COPYING in this directory.
 */

/***********************************************************************
  module:       options.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:	command-line option processing

 ***********************************************************************/

#include <config.h>
#include <stdio.h>

#include <pwd.h>
#include "getopt.h"
#include "popclient.h"
#include "bzero.h"

/* XXX -- Would like to use 'enum' here, but it causes type mismatch 
          problems many compilers */
#define LA_VERSION	1 
#define LA_ALL          2
#define LA_KILL		3
#define	LA_KEEP		4 
#define LA_VERBOSE	5 
#define LA_SILENT	6 
#define LA_STDOUT	7
#define LA_LIMIT	8
#define LA_FLUSH        9
#define LA_PROTOCOL	10
#define LA_DAEMON	11
#define LA_POPRC	12
#define LA_USERNAME	13
#define LA_REMOTEFILE	14
#define	LA_LOCALFILE	15
#define LA_MDA		16
#define LA_LOGFILE	17
#define LA_QUIT		18
#define LA_YYDEBUG	19
 
static char *shortoptions = "23VaKkvscl:Fd:f:u:r:o:m:";
static struct option longoptions[] = {
  {"version",   no_argument,       (int *) 0, LA_VERSION    },
  {"all",	no_argument,       (int *) 0, LA_ALL        },
  {"kill",	no_argument,	   (int *) 0, LA_KILL       },
  {"keep",      no_argument,       (int *) 0, LA_KEEP       },
  {"verbose",   no_argument,       (int *) 0, LA_VERBOSE    },
  {"silent",    no_argument,       (int *) 0, LA_SILENT     },
  {"stdout",    no_argument,       (int *) 0, LA_STDOUT     },
  {"limit",     required_argument, (int *) 0, LA_LIMIT      },
  {"flush",	no_argument,	   (int *) 0, LA_FLUSH      },
  {"protocol",	required_argument, (int *) 0, LA_PROTOCOL   },
  {"proto",	required_argument, (int *) 0, LA_PROTOCOL   },
  {"daemon",	required_argument, (int *) 0, LA_DAEMON     },
  {"poprc",	required_argument, (int *) 0, LA_POPRC      },
  {"user",	required_argument, (int *) 0, LA_USERNAME   },
  {"username",  required_argument, (int *) 0, LA_USERNAME   },
  {"remote",    required_argument, (int *) 0, LA_REMOTEFILE },
  {"local",     required_argument, (int *) 0, LA_LOCALFILE  },
  {"mda",	required_argument, (int *) 0, LA_MDA        },
  {"logfile",	required_argument, (int *) 0, LA_LOGFILE    },
  {"quit",	no_argument,	   (int *) 0, LA_QUIT       },
  {"yydebug",	no_argument,	   (int *) 0, LA_YYDEBUG    },
  {(char *) 0,  no_argument,       (int *) 0, 0             }
};


/*********************************************************************
  function:      parsecmdline
  description:   parse/validate the command line options.
  arguments:
    argc         argument count.
    argv         argument strings.
    options      pointer to a struct hostrec to receive the parsed 
                 options.

  return value:  if positive, argv index of last parsed option + 1
		 (presumes one or more server names follows).
		 if zero, the command line switches are such that
		 no server names are required (e.g. --version).
		 if negative, the command line is has one or more
	   	 syntax errors.
  calls:         none.  
  globals:       writes outlevel, versioninfo, yydebug, logfile, 
		 poll_interval, quitmode, poprcfile, linelimit.  
 *********************************************************************/

int parsecmdline (argc,argv,options)
int argc;
char **argv;
struct hostrec *options;
{
  int c,i;
  int fflag = 0;     /* TRUE when -o or -c has been specified */
  int errflag = 0;   /* TRUE when a syntax error is detected */
  int option_index;
  int got_kill = 0;  /* TRUE when --kill is specified */

  extern int optind, opterr;     /* defined in getopt(2) */
  extern char *optarg;          /* defined in getopt(2) */

  bzero(options,sizeof(struct hostrec));    /* start clean */

  while (!errflag && 
         (c = getopt_long(argc,argv,shortoptions,
                          longoptions,&option_index)) != -1) {

    switch (c) {
      case '2':
        options->protocol = P_POP2;
        break;
      case '3':
        options->protocol = P_POP3;
        break;
      case 'V':
      case LA_VERSION:
        versioninfo = !0;
        break;
      case 'a':
      case LA_ALL:
        options->fetchall = !0;
        break;
      case 'K':
      case LA_KILL:
        options->keep = 0;
        got_kill = 1;
        break;
      case 'k':
      case LA_KEEP:
        options->keep = !0;
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
      case 'c':
      case LA_STDOUT:
        if (fflag)
          errflag++;
        else {
          fflag++;
          options->output = TO_STDOUT;
        }
        break;
      case 'l':
      case LA_LIMIT:
        linelimit = atoi(optarg);
        if (linelimit < 0) {
          fprintf(stderr,"Line count limit must be non-negative");
          errflag++;
        }
        break;
      case 'F':
      case LA_FLUSH:
        options->flush = !0;
        break;
      case LA_PROTOCOL:
        /* XXX -- should probably use a table lookup here */
        if (strcasecmp(optarg,"pop2") == 0)
          options->protocol = P_POP2;
        else if (strcasecmp(optarg,"pop3") == 0)
          options->protocol = P_POP3;
        else if (strcasecmp(optarg,"imap") == 0)
          options->protocol = P_IMAP;
        else if (strcasecmp(optarg,"apop") == 0)
          options->protocol = P_APOP;
        else if (strcasecmp(optarg,"rpop") == 0)
          options->protocol = P_RPOP;
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
      case LA_POPRC:
        poprcfile = (char *) xmalloc(strlen(optarg)+1);
        strcpy(poprcfile,optarg);
        break;
      case 'u':
      case LA_USERNAME:
        strncpy(options->remotename,optarg,sizeof(options->remotename)-1);
        break;
      case 'o':
      case LA_LOCALFILE:
        if (fflag) 
          errflag++;
        else {
          fflag++;
          options->output = TO_FOLDER;
          strncpy(options->userfolder,optarg,sizeof(options->userfolder)-1);
        }
        break;
      case 'r':
      case LA_REMOTEFILE:
        strncpy(options->remotefolder,optarg,sizeof(options->remotefolder)-1);
        break;
      case 'm':
      case LA_MDA:
        strncpy(options->mda,optarg,sizeof(options->mda)-1);
        break;
      case 'L':
      case LA_LOGFILE:
        logfile = optarg;
        break;
      case 'q':
      case LA_QUIT:
        quitmode = 1;
        break;
      case LA_YYDEBUG:
	yydebug = 1;
        break;
      default:
        errflag++;
    }
  }

  if (errflag) {
    /* squawk if syntax errors were detected */
    fputs("usage:  popclient [options] [server ...]\n", stderr);
    fputs("  options\n",stderr);
    fputs("  -2               use POP2 protocol\n", stderr);
    fputs("  -3               use POP3 protocol\n", stderr);
    fputs("      --protocol   specify pop2, pop3, imap, apop, or rpop\n",
          stderr);
    fputs("  -V, --version    display version info\n", stderr);
    fputs("  -a, --all        retrieve old and new messages\n", stderr);
    fputs("  -F, --flush      delete old messages from server\n", stderr);
    fputs("  -K, --kill       delete new messages after retrieval\n", stderr);
    fputs("  -k, --keep       save new messages after retrieval\n", stderr);
    fputs("  -l, --limit      retrieve at most n message lines\n", stderr);
    fputs("  -m, --mda        set mail user agent to pass to\n", stderr);
    fputs("  -q, --quit       kill daemon process\n", stderr);
    fputs("  -s, --silent     work silently\n", stderr);
    fputs("  -v, --verbose    work noisily (diagnostic output)\n", stderr);
    fputs("  -d, --daemon     run as a daemon once per n seconds\n", stderr);
    fputs("  -f, --poprc      specify alternate config file\n", stderr);
    fputs("  -u, --username   specify server user ID\n", stderr);
    fputs("  -c, --stdout     write received mail to stdout\n", stderr);
    fputs("  -o, --local      specify filename for received mail\n", stderr);
    fputs("  -r, --remote     specify remote folder name\n", stderr);
    fputs("  -L, --logfile    specify logfile name\n", stderr);
    return(-1);
  }
  else {
    if (linelimit && !got_kill) 
      options->keep = !0;
    else
      ;
    return(optind);
  }
}
         

/*********************************************************************
  function:      setdefaults
  description:   set reasonable default values for unspecified options.
  arguments:     
    options      option values parsed from the command-line; unspeci-
                 fied options must be filled with zero.

  return value:  zero if defaults were successfully set, else non-zero
                 (indicates a problem reading /etc/passwd).
  calls:         none.
  globals:       writes outlevel, poprcfile.
 *********************************************************************/

int setdefaults (options)
struct hostrec *options;
{
  int uid;
  struct passwd *pw;
  char *mailvar;

  bzero(options,sizeof(*options));

  if ((pw = getpwuid(uid = getuid())) == NULL) {
    fprintf(stderr,"No passwd entry for uid %d\n",uid);
    return(-1);
  }

  options->protocol = DEF_PROTOCOL;

#if defined(KEEP_IS_DEFAULT)
  options->keep = 1;
#else
  options->keep = 0;
#endif

  strcpy(options->localname,pw->pw_name);
  strcpy(options->remotename,pw->pw_name);

#if defined(USERFOLDER) && defined(HAVE_FLOCK) 
  options->output = TO_FOLDER;
  sprintf(options->userfolder, USERFOLDER, pw->pw_name);
#else
  options->output = TO_MDA;
#endif

  (void) sprintf(options->mda, DEF_MDA, options->localname);

  poprcfile = 
      (char *) xmalloc(strlen(pw->pw_dir)+strlen(POPRC_NAME)+2);

  strcpy(poprcfile, pw->pw_dir);
  strcat(poprcfile, "/");
  strcat(poprcfile, POPRC_NAME);

  outlevel = O_NORMAL;

  return(0);
}



/******************************************************************
  function:	getnextserver
  description:	read next server name from the command line.
  arguments:	
    argc	from main()
    argv	from main()
    optind	as returned by parsecmdline and this function.

  ret. value:	next server name from command line or NULL if all
	        server names have been retrieved.
  globals:	none.
  calls:	none.
 *****************************************************************/
char *getnextserver (argc,argv,optind)
int argc;
char **argv;
int *optind;
{
   if (*optind >= argc) {
     /* no more servers */
     return((char *) 0);
   }
   else
     return(argv[(*optind)++]);
}
