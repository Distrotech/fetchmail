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
  module:       options.c
  project:      popclient
  programmer:   Carl Harris, ceharris@mal.com
  description:	command-line option processing
  
  $Log: options.c,v $
  Revision 1.3  1996/06/27 19:22:32  esr
  Sent to ceharris.

  Revision 1.2  1996/06/26 19:08:57  esr
  This is what I sent Harris.

  Revision 1.1  1996/06/24 18:11:08  esr
  Initial revision

  Revision 1.4  1995/08/14 18:36:39  ceharris
  Patches to support POP3's LAST command.
  Final revisions for beta3 release.

  Revision 1.3  1995/08/10 00:32:34  ceharris
  Preparation for 3.0b3 beta release:
  -	added code for --kill/--keep, --limit, --protocol, --flush
  	options; --pop2 and --pop3 options now obsoleted by --protocol.
  - 	added support for APOP authentication, including --with-APOP
  	argument for configure.
  -	provisional and broken support for RPOP
  -	added buffering to SockGets and SockRead functions.
  -	fixed problem of command-line options not being correctly
  	carried into the merged options record.

  Revision 1.2  1995/08/09 01:32:51  ceharris
  Version 3.0 beta 2 release.
  Added
  -	.poprc functionality
  -	GNU long options
  -	multiple servers on the command line.
  Fixed
  -	Passwords showing up in ps output.

  Revision 1.1  1995/08/08 01:01:21  ceharris
  Added GNU-style long options processing.
  Fixed password in 'ps' output problem.
  Fixed various RCS tag blunders.
  Integrated .poprc parser, lexer, etc into Makefile processing.

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
    options      pointer to a struct optrec to receive the parsed 
                 options.

  return value:  if positive, argv index of last parsed option + 1
		 (presumes one or more server names follows).
		 if zero, the command line switches are such that
		 no server names are required (e.g. --version).
		 if negative, the command line is has one or more
	   	 syntax errors.
  calls:         none.  
  globals:       none.  
 *********************************************************************/

int parsecmdline (argc,argv,options)
int argc;
char **argv;
struct optrec *options;
{
  int c,i;
  int fflag = 0;     /* TRUE when -o or -c has been specified */
  int errflag = 0;   /* TRUE when a syntax error is detected */
  int option_index;
  int got_kill = 0;  /* TRUE when --kill is specified */

  extern int optind, opterr;     /* defined in getopt(2) */
  extern char *optarg;          /* defined in getopt(2) */

  bzero(options,sizeof(struct optrec));    /* start clean */

  while (!errflag && 
         (c = getopt_long(argc,argv,shortoptions,
                          longoptions,&option_index)) != -1) {

    switch (c) {
      case '2':
        options->whichpop = P_POP2;
        break;
      case '3':
        options->whichpop = P_POP3;
        break;
      case 'V':
      case LA_VERSION:
        options->versioninfo = !0;
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
        options->verbose = !0;
        break;
      case 's':
      case LA_SILENT:
        options->silent = !0;
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
        options->limit = atoi(optarg);
        if (options->limit < 0) {
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
          options->whichpop = P_POP2;
        else if (strcasecmp(optarg,"pop3") == 0)
          options->whichpop = P_POP3;
        else if (strcasecmp(optarg,"imap") == 0)
          options->whichpop = P_IMAP;
        else if (strcasecmp(optarg,"apop") == 0)
          options->whichpop = P_APOP;
        else if (strcasecmp(optarg,"rpop") == 0)
          options->whichpop = P_RPOP;
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
        options->poprcfile = (char *) xmalloc(strlen(optarg)+1);
        strcpy(options->poprcfile,optarg);
        break;
      case 'u':
      case LA_USERNAME:
        strncpy(options->username,optarg,sizeof(options->username)-1);
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
    if (options->limit && !got_kill) 
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
  globals:       writes outlevel.
 *********************************************************************/

int setdefaults (options)
struct optrec *options;
{
  int uid;
  struct passwd *pw;
  char *mailvar;

  bzero(options,sizeof(*options));

  if ((pw = getpwuid(uid = getuid())) == NULL) {
    fprintf(stderr,"No passwd entry for uid %d\n",uid);
    return(-1);
  }
  /* save the login name for delivery use */
  strcpy(options->loginid,pw->pw_name);

  options->whichpop = DEF_PROTOCOL;

#if defined(KEEP_IS_DEFAULT)
  options->keep = 1;
#else
  options->keep = 0;
#endif

  strcpy(options->username,pw->pw_name);

#if defined(USERFOLDER) && defined(HAVE_FLOCK) 
  options->output = TO_FOLDER;
  sprintf(options->userfolder, USERFOLDER, options->username);
#else
  options->output = TO_MDA;
#endif

  (void) sprintf(options->mda, DEF_MDA, options->username);

  options->poprcfile = 
      (char *) xmalloc(strlen(pw->pw_dir)+strlen(POPRC_NAME)+2);

  strcpy(options->poprcfile, pw->pw_dir);
  strcat(options->poprcfile, "/");
  strcat(options->poprcfile, POPRC_NAME);

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
