/*
 * options.c -- command-line option processing
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>

#include <stdio.h>
#include <pwd.h>
#include <string.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif

#include "getopt.h"
#include "fetchmail.h"

#define LA_HELP		1
#define LA_VERSION	2 
#define LA_CHECK	3
#define LA_SILENT	4 
#define LA_VERBOSE	5 
#define LA_DAEMON	6
#define LA_NODETACH	7
#define LA_QUIT		8
#define LA_LOGFILE	9
#define LA_RCFILE	10
#define LA_IDFILE	11
#define LA_PROTOCOL	12
#define LA_PORT		13
#define LA_AUTHENTICATE	14
#define LA_TIMEOUT	15
#define LA_USERNAME	16
#define LA_ALL          17
#define LA_KILL		18
#define	LA_KEEP		19
#define LA_FLUSH        20
#define LA_NOREWRITE	21
#define LA_LIMIT	22
#define LA_REMOTEFILE	23
#define LA_SMTPHOST	24
#define LA_MDA		25
#define LA_YYDEBUG	26

static char *shortoptions = "?Vcsvd:NqL:f:i:p:P:A:t:u:akKFnl:r:S:m:y";
static struct option longoptions[] = {
  {"help",	no_argument,	   (int *) 0, LA_HELP        },
  {"version",   no_argument,       (int *) 0, LA_VERSION     },
  {"check",	no_argument,	   (int *) 0, LA_CHECK       },
  {"silent",    no_argument,       (int *) 0, LA_SILENT      },
  {"verbose",   no_argument,       (int *) 0, LA_VERBOSE     },
  {"daemon",	required_argument, (int *) 0, LA_DAEMON      },
  {"nodetach",	no_argument,	   (int *) 0, LA_NODETACH    },
  {"quit",	no_argument,	   (int *) 0, LA_QUIT        },
  {"logfile",	required_argument, (int *) 0, LA_LOGFILE     },
  {"fetchmailrc",required_argument,(int *) 0, LA_RCFILE      },
  {"idfile",	required_argument, (int *) 0, LA_IDFILE      },

  {"protocol",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"proto",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"port",	required_argument, (int *) 0, LA_PORT        },
  {"auth",	required_argument, (int *) 0, LA_AUTHENTICATE},
  {"timeout",	required_argument, (int *) 0, LA_TIMEOUT     },

  {"user",	required_argument, (int *) 0, LA_USERNAME    },
  {"username",  required_argument, (int *) 0, LA_USERNAME    },

  {"all",	no_argument,       (int *) 0, LA_ALL         },
  {"kill",	no_argument,	   (int *) 0, LA_KILL        },
  {"keep",      no_argument,       (int *) 0, LA_KEEP        },
  {"flush",	no_argument,	   (int *) 0, LA_FLUSH       },
  {"norewrite",	no_argument,	   (int *) 0, LA_NOREWRITE   },
  {"limit",	required_argument, (int *) 0, LA_LIMIT       },

  {"remote",    required_argument, (int *) 0, LA_REMOTEFILE  },
  {"smtphost",	required_argument, (int *) 0, LA_SMTPHOST    },
  {"mda",	required_argument, (int *) 0, LA_MDA         },

  {"yydebug",	no_argument,	   (int *) 0, LA_YYDEBUG     },

  {(char *) 0,  no_argument,       (int *) 0, 0              }
};

int parsecmdline (argc, argv,ctl)
/* parse and validate the command line options */
int argc;			/* argument count */
char **argv;			/* argument strings */
struct query *ctl;	/* option record to be initialized */
{
    /*
     * return value: if positive, argv index of last parsed option + 1
     * (presumes one or more server names follows).  if zero, the
     * command line switches are such that no server names are
     * required (e.g. --version).  if negative, the command line is
     * has one or more syntax errors.
     */

    int c;
    int ocount = 0;     /* count of destinations specified */
    int errflag = 0;   /* TRUE when a syntax error is detected */
    int option_index;

    memset(ctl, '\0', sizeof(struct query));    /* start clean */

    while (!errflag && 
	   (c = getopt_long(argc,argv,shortoptions,
			    longoptions,&option_index)) != -1) {

	switch (c) {
	case 'V':
	case LA_VERSION:
	    versioninfo = TRUE;
	    break;
	case 'c':
	case LA_CHECK:
	    check_only = TRUE;
	    break;
	case 's':
	case LA_SILENT:
	    outlevel = O_SILENT;
	    break;
	case 'v':
	case LA_VERBOSE:
	    outlevel = O_VERBOSE;
	    break;
	case 'd':
	case LA_DAEMON:
	    poll_interval = atoi(optarg);
	    ctl->fetchall = TRUE;
	    break;
	case 'N':
	case LA_NODETACH:
	    nodetach = TRUE;
	    break;
	case 'q':
	case LA_QUIT:
	    quitmode = TRUE;
	    break;
	case 'L':
	case LA_LOGFILE:
	    logfile = optarg;
	    break;
	case 'f':
	case LA_RCFILE:
	    rcfile = (char *) xmalloc(strlen(optarg)+1);
	    strcpy(rcfile,optarg);
	    break;
	case 'i':
	case LA_IDFILE:
	    idfile = (char *) xmalloc(strlen(optarg)+1);
	    strcpy(idfile,optarg);
	    break;
	case 'p':
	case LA_PROTOCOL:
	    /* XXX -- should probably use a table lookup here */
	    if (strcasecmp(optarg,"pop2") == 0)
		ctl->protocol = P_POP2;
	    else if (strcasecmp(optarg,"pop3") == 0)
		ctl->protocol = P_POP3;
	    else if (strcasecmp(optarg,"imap") == 0)
		ctl->protocol = P_IMAP;
	    else if (strcasecmp(optarg,"apop") == 0)
		ctl->protocol = P_APOP;
	    else if (strcasecmp(optarg,"kpop") == 0)
	    {
		ctl->protocol = P_POP3;
		ctl->port = KPOP_PORT;
		ctl->authenticate =  A_KERBEROS;
	    }
	    else {
		fprintf(stderr,"Invalid protocol `%s' specified.\n", optarg);
		errflag++;
	    }
	    break;
	case 'P':
	case LA_PORT:
	    ctl->port = atoi(optarg);
	    break;
	case 'A':
	case LA_AUTHENTICATE:
	    if (strcmp(optarg, "password") == 0)
		ctl->authenticate = A_PASSWORD;
	    else if (strcmp(optarg, "kerberos") == 0)
		ctl->authenticate = A_KERBEROS;
	    else {
		fprintf(stderr,"Invalid authentication `%s' specified.\n", optarg);
		errflag++;
	    }
	    break;
	case 't':
	    ctl->timeout = atoi(optarg);
	    break;
	case 'u':
	case LA_USERNAME:
	    strncpy(ctl->remotename,optarg,sizeof(ctl->remotename)-1);
	    break;

	case 'a':
	case LA_ALL:
	    ctl->fetchall = TRUE;
	    break;
	case 'K':
	case LA_KILL:
	    ctl->keep = FALSE;
	    break;
	case 'k':
	case LA_KEEP:
	    ctl->keep = TRUE;
	    break;
	case 'F':
	case LA_FLUSH:
	    ctl->flush = TRUE;
	    break;
	case 'n':
	case LA_NOREWRITE:
	    ctl->norewrite = TRUE;
	    break;
	case 'l':
	case LA_LIMIT:
	    ctl->limit = atoi(optarg);
	    break;
	case 'r':
	case LA_REMOTEFILE:
	    strncpy(ctl->mailbox,optarg,sizeof(ctl->mailbox)-1);
	    break;
	case 'S':
	case LA_SMTPHOST:
	    strncpy(ctl->smtphost,optarg,sizeof(ctl->smtphost)-1);
	    ocount++;
	    break;
	case 'm':
	case LA_MDA:
	    strncpy(ctl->mda,optarg,sizeof(ctl->mda));
	    ocount++;
	    break;
	case 'y':
	case LA_YYDEBUG:
	    yydebug = TRUE;
	    break;

	case '?':
	case LA_HELP:
	default:
	    errflag++;
	}
    }

    if (check_only && poll_interval)
    {
	fputs("The --check and --daemon options aren't compatible.\n", stderr);
	return(-1);
    }

    if (errflag || ocount > 1) {
	/* squawk if syntax errors were detected */
	fputs("usage:  fetchmail [options] [server ...]\n", stderr);
	fputs("  Options are as follows:\n",stderr);
	fputs("  -?, --help        display this option help\n", stderr);
	fputs("  -V, --version     display version info\n", stderr);

	fputs("  -c, --check       check for messages without fetching\n", stderr);
	fputs("  -s, --silent      work silently\n", stderr);
	fputs("  -v, --verbose     work noisily (diagnostic output)\n", stderr);
	fputs("  -d, --daemon      run as a daemon once per n seconds\n", stderr);
	fputs("  -N, --nodetach    don't detach daemon process\n", stderr);
	fputs("  -q, --quit        kill daemon process\n", stderr);
	fputs("  -L, --logfile     specify logfile name\n", stderr);
	fputs("  -f, --fetchmailrc specify alternate run control file\n", stderr);
	fputs("  -i, --idfile      specify alternate UIDs file\n", stderr);

	fputs("  -p, --protocol    specify pop2, pop3, imap, apop, rpop, kpop\n", stderr);
	fputs("  -P, --port        TCP/IP service port to connect to\n",stderr);
	fputs("  -A, --auth        authentication type (password or kerberos)\n",stderr);
	fputs("  -t, --timeout     server nonresponse timeout\n",stderr);

	fputs("  -u, --username    specify users's login on server\n", stderr);
	fputs("  -a, --all         retrieve old and new messages\n", stderr);
	fputs("  -K, --kill        delete new messages after retrieval\n", stderr);
	fputs("  -k, --keep        save new messages after retrieval\n", stderr);
	fputs("  -F, --flush       delete old messages from server\n", stderr);
	fputs("  -n, --norewrite   don't rewrite header addresses\n", stderr);
	fputs("  -l, --limit       don't fetch messages over given size\n", stderr);

	fputs("  -S, --smtphost    set SMTP forwarding host\n", stderr);
	fputs("  -r, --remote      specify remote folder name\n", stderr);
	return(-1);
    }

    return(optind);
}

/* options.c ends here */
