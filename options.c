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
#define LA_SYSLOG	10
#define LA_RCFILE	11
#define LA_IDFILE	12
#define LA_PROTOCOL	13
#define LA_UIDL		14
#define LA_PORT		15
#define LA_AUTHENTICATE	16
#define LA_TIMEOUT	17
#define LA_ENVELOPE	18
#define LA_USERNAME	19
#define LA_ALL          20
#define LA_KILL		21
#define	LA_KEEP		22
#define LA_FLUSH        23
#define LA_NOREWRITE	24
#define LA_LIMIT	25
#define LA_FOLDER	26
#define LA_SMTPHOST	27
#define LA_BATCHLIMIT	28
#define LA_FETCHLIMIT	29
#define LA_MDA		30
#define LA_INTERFACE    31
#define LA_MONITOR      32
#define LA_YYDEBUG	33

static char *shortoptions = "?Vcsvd:NqL:f:i:p:UP:A:t:E:u:akKFnl:r:S:b:B:m:I:M:y";
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
  {"syslog",	no_argument,	   (int *) 0, LA_SYSLOG      },
  {"fetchmailrc",required_argument,(int *) 0, LA_RCFILE      },
  {"idfile",	required_argument, (int *) 0, LA_IDFILE      },

  {"protocol",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"proto",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"uidl",	no_argument,	   (int *) 0, LA_UIDL	     },
  {"port",	required_argument, (int *) 0, LA_PORT        },
  {"auth",	required_argument, (int *) 0, LA_AUTHENTICATE},
  {"timeout",	required_argument, (int *) 0, LA_TIMEOUT     },
  {"envelope",	required_argument, (int *) 0, LA_ENVELOPE    },

  {"user",	required_argument, (int *) 0, LA_USERNAME    },
  {"username",  required_argument, (int *) 0, LA_USERNAME    },

  {"all",	no_argument,       (int *) 0, LA_ALL         },
  {"kill",	no_argument,	   (int *) 0, LA_KILL        },
  {"keep",      no_argument,       (int *) 0, LA_KEEP        },
  {"flush",	no_argument,	   (int *) 0, LA_FLUSH       },
  {"norewrite",	no_argument,	   (int *) 0, LA_NOREWRITE   },
  {"limit",	required_argument, (int *) 0, LA_LIMIT       },

  {"folder",    required_argument, (int *) 0, LA_FOLDER  },
  {"smtphost",	required_argument, (int *) 0, LA_SMTPHOST    },
  {"batchlimit",required_argument, (int *) 0, LA_BATCHLIMIT  },
  {"fetchlimit",required_argument, (int *) 0, LA_FETCHLIMIT  },
  {"mda",	required_argument, (int *) 0, LA_MDA         },

#ifdef	linux
  {"interface",	required_argument, (int *) 0, LA_INTERFACE   },
  {"monitor",	required_argument, (int *) 0, LA_MONITOR     },
#endif

  {"yydebug",	no_argument,	   (int *) 0, LA_YYDEBUG     },

  {(char *) 0,  no_argument,       (int *) 0, 0              }
};

int parsecmdline (argc, argv, ctl)
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
    char buf[BUFSIZ], *cp;

    cmd_daemon = -1;

    memset(ctl, '\0', sizeof(struct query));    /* start clean */
    ctl->smtp_socket = -1;

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
	    cmd_daemon = atoi(optarg);
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
	    cmd_logfile = optarg;
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
		ctl->server.protocol = P_POP2;
	    else if (strcasecmp(optarg,"pop3") == 0)
		ctl->server.protocol = P_POP3;
	    else if (strcasecmp(optarg,"apop") == 0)
		ctl->server.protocol = P_APOP;
	    else if (strcasecmp(optarg,"rpop") == 0)
		ctl->server.protocol = P_RPOP;
	    else if (strcasecmp(optarg,"kpop") == 0)
	    {
		ctl->server.protocol = P_POP3;
		ctl->server.port = KPOP_PORT;
		ctl->server.preauthenticate =  A_KERBEROS_V4;
	    }
	    else if (strcasecmp(optarg,"imap") == 0)
		ctl->server.protocol = P_IMAP;
#ifdef KERBEROS_V4
	    else if (strcasecmp(optarg,"imap-k4") == 0)
		ctl->server.protocol = P_IMAP_K4;
#endif /* KERBEROS_V4 */
	    else if (strcasecmp(optarg,"etrn") == 0)
		ctl->server.protocol = P_ETRN;
	    else {
		fprintf(stderr,"Invalid protocol `%s' specified.\n", optarg);
		errflag++;
	    }
	    break;
	case 'U':
	case LA_UIDL:
	    ctl->server.uidl = FLAG_TRUE;
	    break;
	case 'P':
	case LA_PORT:
	    ctl->server.port = atoi(optarg);
	    break;
	case 'A':
	case LA_AUTHENTICATE:
	    if (strcmp(optarg, "password") == 0)
		ctl->server.preauthenticate = A_PASSWORD;
	    else if (strcmp(optarg, "kerberos") == 0)
		ctl->server.preauthenticate = A_KERBEROS_V4;
	    else if (strcmp(optarg, "kerberos_v4") == 0)
		ctl->server.preauthenticate = A_KERBEROS_V4;
	    else {
		fprintf(stderr,"Invalid preauthentication `%s' specified.\n", optarg);
		errflag++;
	    }
	    break;
	case 't':
	case LA_TIMEOUT:
	    ctl->server.timeout = atoi(optarg);
	    if (ctl->server.timeout == 0)
		ctl->server.timeout = -1;
	    break;
	case 'E':
	case LA_ENVELOPE:
	    ctl->server.envelope = xstrdup(optarg);
	    break;

	case 'u':
	case LA_USERNAME:
	    ctl->remotename = xstrdup(optarg);
	    break;
	case 'a':
	case LA_ALL:
	    ctl->fetchall = FLAG_TRUE;
	    break;
	case 'K':
	case LA_KILL:
	    ctl->keep = FLAG_FALSE;
	    break;
	case 'k':
	case LA_KEEP:
	    ctl->keep = FLAG_TRUE;
	    break;
	case 'F':
	case LA_FLUSH:
	    ctl->flush = FLAG_TRUE;
	    break;
	case 'n':
	case LA_NOREWRITE:
	    ctl->rewrite = FLAG_FALSE;
	    break;
	case 'l':
	case LA_LIMIT:
	    ctl->limit = atoi(optarg);
	    if (ctl->limit == 0)
		ctl->limit = -1;
	    break;
	case 'r':
	case LA_FOLDER:
	    strcpy(buf, optarg);
	    cp = strtok(buf, ",");
	    do {
		save_str(&ctl->mailboxes, -1, optarg);
	    } while
		((cp = strtok((char *)NULL, ",")));
	    break;
	case 'S':
	case LA_SMTPHOST:
	    strcpy(buf, optarg);
	    cp = strtok(buf, ",");
	    do {
		save_str(&ctl->smtphunt, -1, optarg);
	    } while
		((cp = strtok((char *)NULL, ",")));
	    ocount++;
	    break;
	case 'b':
	case LA_BATCHLIMIT:
	    ctl->batchlimit = atoi(optarg);
	    if (ctl->batchlimit == 0)
		ctl->batchlimit = -1;
	    break;
	case 'B':
	case LA_FETCHLIMIT:
	    ctl->fetchlimit = atoi(optarg);
	    if (ctl->fetchlimit == 0)
		ctl->fetchlimit = -1;
	    break;
	case 'm':
	case LA_MDA:
	    ctl->mda = xstrdup(optarg);
	    ocount++;
	    break;

#ifdef	linux
	case 'I':
	case LA_INTERFACE:
	    interface_parse(optarg, &ctl->server);
	    break;
	case 'M':
	case LA_MONITOR:
	    ctl->server.monitor = xstrdup(optarg);
	    break;
#endif

	case 'y':
	case LA_YYDEBUG:
	    yydebug = TRUE;
	    break;

	case LA_SYSLOG:
	    use_syslog = TRUE;
	    break;

	case '?':
	case LA_HELP:
	default:
	    errflag++;
	}
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
	fputs("      --syslog      use syslog(3) for most messages when running as a daemon\n", stderr);
	fputs("  -f, --fetchmailrc specify alternate run control file\n", stderr);
	fputs("  -i, --idfile      specify alternate UIDs file\n", stderr);
#ifdef	linux
	fputs("  -I, --interface   interface required specification\n",stderr);
	fputs("  -M, --monitor     monitor interface for activity\n",stderr);
#endif

#ifdef KERBEROS_V4
	fputs("  -p, --protocol    specify pop2, pop3, imap, apop, rpop, kpop, etrn, imap-k4\n", stderr);
#else
	fputs("  -p, --protocol    specify pop2, pop3, imap, apop, rpop, kpop, etrn\n", stderr);
#endif /* KERBEROS_V4 */
	fputs("  -U, --uidl        force the use of UIDLs (pop3 only)\n", stderr);
	fputs("  -P, --port        TCP/IP service port to connect to\n",stderr);
	fputs("  -A, --auth        authentication type (password or kerberos)\n",stderr);
	fputs("  -t, --timeout     server nonresponse timeout\n",stderr);
	fputs("  -E, --envelope    envelope address header\n",stderr);

	fputs("  -u, --username    specify users's login on server\n", stderr);
	fputs("  -a, --all         retrieve old and new messages\n", stderr);
	fputs("  -K, --kill        delete new messages after retrieval\n", stderr);
	fputs("  -k, --keep        save new messages after retrieval\n", stderr);
	fputs("  -F, --flush       delete old messages from server\n", stderr);
	fputs("  -n, --norewrite   don't rewrite header addresses\n", stderr);
	fputs("  -l, --limit       don't fetch messages over given size\n", stderr);

	fputs("  -S, --smtphost    set SMTP forwarding host\n", stderr);
	fputs("  -b, --batchlimit  set batch limit for SMTP connections\n", stderr);
	fputs("  -B, --fetchlimit  set fetch limit for server connections\n", stderr);
	fputs("  -r, --folder      specify remote folder name\n", stderr);
	return(-1);
    }

    return(optind);
}

/* options.c ends here */
