/*
 * options.c -- command-line option processing
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"

#include <stdio.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#include  <limits.h>
#else
#include  <ctype.h>
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
#define LA_INVISIBLE	10
#define LA_SYSLOG	11
#define LA_NOSYSLOG	12
#define LA_RCFILE	13
#define LA_IDFILE	14
#define LA_POSTMASTER	15
#define LA_PROTOCOL	16
#define LA_UIDL		17
#define LA_PORT		18
#define LA_AUTHENTICATE	19
#define LA_TIMEOUT	20
#define LA_ENVELOPE	21
#define LA_QVIRTUAL     22
#define LA_USERNAME	23
#define LA_ALL          24
#define LA_NOKEEP	25
#define	LA_KEEP		26
#define LA_FLUSH        27
#define LA_NOREWRITE	28
#define LA_LIMIT	29
#define LA_FOLDER	30
#define LA_SMTPHOST	31
#define LA_SMTPADDR     32
#define LA_ANTISPAM	33
#define LA_BATCHLIMIT	34
#define LA_FETCHLIMIT	35
#define LA_EXPUNGE	36
#define LA_MDA		37
#define LA_NETSEC	38
#define LA_INTERFACE    39
#define LA_MONITOR      41
#define LA_CONFIGDUMP	42
#define LA_YYDEBUG	43

/* options still left: CgGhHjJoORwWxXYz */
static const char *shortoptions = 
	"?Vcsvd:NqL:f:i:p:UP:A:t:E:Q:u:akKFnl:r:S:Z:b:B:e:m:T:I:M:y";

static const struct option longoptions[] = {
/* this can be const because all flag fields are 0 and will never get set */
  {"help",	no_argument,	   (int *) 0, LA_HELP        },
  {"version",   no_argument,       (int *) 0, LA_VERSION     },
  {"check",	no_argument,	   (int *) 0, LA_CHECK       },
  {"silent",    no_argument,       (int *) 0, LA_SILENT      },
  {"verbose",   no_argument,       (int *) 0, LA_VERBOSE     },
  {"daemon",	required_argument, (int *) 0, LA_DAEMON      },
  {"nodetach",	no_argument,	   (int *) 0, LA_NODETACH    },
  {"quit",	no_argument,	   (int *) 0, LA_QUIT        },
  {"logfile",	required_argument, (int *) 0, LA_LOGFILE     },
  {"invisible",	no_argument,	   (int *) 0, LA_INVISIBLE   },
  {"syslog",	no_argument,	   (int *) 0, LA_SYSLOG      },
  {"nosyslog",	no_argument,	   (int *) 0, LA_NOSYSLOG    },
  {"fetchmailrc",required_argument,(int *) 0, LA_RCFILE      },
  {"idfile",	required_argument, (int *) 0, LA_IDFILE      },
  {"postmaster",required_argument, (int *) 0, LA_POSTMASTER  },

  {"protocol",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"proto",	required_argument, (int *) 0, LA_PROTOCOL    },
  {"uidl",	no_argument,	   (int *) 0, LA_UIDL	     },
  {"port",	required_argument, (int *) 0, LA_PORT        },
  {"auth",	required_argument, (int *) 0, LA_AUTHENTICATE},
  {"timeout",	required_argument, (int *) 0, LA_TIMEOUT     },
  {"envelope",	required_argument, (int *) 0, LA_ENVELOPE    },
  {"qvirtual",	required_argument, (int *) 0, LA_QVIRTUAL    },

  {"user",	required_argument, (int *) 0, LA_USERNAME    },
  {"username",  required_argument, (int *) 0, LA_USERNAME    },

  {"all",	no_argument,       (int *) 0, LA_ALL         },
  {"nokeep",	no_argument,	   (int *) 0, LA_NOKEEP      },
  {"keep",      no_argument,       (int *) 0, LA_KEEP        },
  {"flush",	no_argument,	   (int *) 0, LA_FLUSH       },
  {"norewrite",	no_argument,	   (int *) 0, LA_NOREWRITE   },
  {"limit",	required_argument, (int *) 0, LA_LIMIT       },

  {"folder",    required_argument, (int *) 0, LA_FOLDER	     },
  {"smtphost",	required_argument, (int *) 0, LA_SMTPHOST    },
  {"smtpaddress", required_argument, (int *) 0, LA_SMTPADDR  },
  {"antispam",	required_argument, (int *) 0, LA_ANTISPAM    },
  
  {"batchlimit",required_argument, (int *) 0, LA_BATCHLIMIT  },
  {"fetchlimit",required_argument, (int *) 0, LA_FETCHLIMIT  },
  {"expunge",   required_argument, (int *) 0, LA_EXPUNGE     },
  {"mda",	required_argument, (int *) 0, LA_MDA         },

#ifdef INET6
  {"netsec",	required_argument, (int *) 0, LA_NETSEC    },
#endif /* INET6 */

#if defined(linux) && !INET6
  {"interface",	required_argument, (int *) 0, LA_INTERFACE   },
  {"monitor",	required_argument, (int *) 0, LA_MONITOR     },
#endif /* defined(linux) && !INET6 */

  {"configdump",no_argument,	   (int *) 0, LA_CONFIGDUMP  },

  {"yydebug",	no_argument,	   (int *) 0, LA_YYDEBUG     },

  {(char *) 0,  no_argument,       (int *) 0, 0              }
};

static int xatoi(char *s, int *errflagptr)
/* do safe conversion from string to number */
{
#if defined (STDC_HEADERS) && defined (LONG_MAX) && defined (INT_MAX)
    /* parse and convert numbers, but also check for invalid characters in
     * numbers
     */

    char *endptr;
    long value;

    errno = 0;

    value = strtol(s, &endptr, 0);

    /* any invalid chars in string? */
    if ( (endptr == s) || (*endptr != '\0') ) {
    	(void) fprintf(stderr, "String '%s' is not a valid number string.\n", s);
	(*errflagptr)++;
	return 0;
    }

    /* is the range valid? */
    if ( (((value == LONG_MAX) || (value == LONG_MIN)) && (errno == ERANGE)) ||
				(value > INT_MAX) || (value < INT_MIN)) {

    	(void) fprintf(stderr, "Value of string '%s' is %s than %d.\n", s,
					(value < 0) ? "smaller": "larger",
					(value < 0) ? INT_MIN : INT_MAX);
	(*errflagptr)++;
	return 0;
    }

    return (int) value;  /* shut up, I know what I'm doing */
#else
    int	i;
    char *dp;
# if defined (STDC_HEADERS)
    size_t	len;
# else
    int		len;
# endif

    /* We do only base 10 conversions here (atoi)! */

    len = strlen(s);
    /* check for leading white spaces */
    for (i = 0; (i < len) && isspace(s[i]); i++)
    	;

    dp = &s[i];

    /* check for +/- */
    if (i < len && (s[i] == '+' || s[i] == '-'))	i++;

    /* skip over digits */
    for ( /* no init */ ; (i < len) && isdigit(s[i]); i++)
    	;

    /* check for trailing garbage */
    if (i != len) {
    	(void) fprintf(stderr, "String '%s' is not a valid number string.\n", s);
    	(*errflagptr)++;
	return 0;
    }

    /* atoi should be safe by now, except for number range over/underflow */
    return atoi(dp);
#endif
}

int parsecmdline (argc, argv, rctl, ctl)
/* parse and validate the command line options */
int argc;		/* argument count */
char **argv;		/* argument strings */
struct runctl *rctl;	/* global run controls to modify */
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
    char *buf, *cp;

    rctl->poll_interval = -1;

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
	    rctl->poll_interval = xatoi(optarg, &errflag);
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
	    rctl->logfile = optarg;
	    break;
	case LA_INVISIBLE:
	    rctl->invisible = TRUE;
	    break;
	case 'f':
	case LA_RCFILE:
	    rcfile = (char *) xmalloc(strlen(optarg)+1);
	    strcpy(rcfile,optarg);
	    break;
	case 'i':
	case LA_IDFILE:
	    rctl->idfile = (char *) xmalloc(strlen(optarg)+1);
	    strcpy(rctl->idfile,optarg);
	    break;
	case LA_POSTMASTER:
	    rctl->postmaster = (char *) xmalloc(strlen(optarg)+1);
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
#if INET6
		ctl->server.service = KPOP_PORT;
#else /* INET6 */
		ctl->server.port = KPOP_PORT;
#endif /* INET6 */
#ifdef KERBEROS_V5
		ctl->server.preauthenticate =  A_KERBEROS_V5;
#else
		ctl->server.preauthenticate =  A_KERBEROS_V4;
#endif /* KERBEROS_V5 */
	    }
	    else if (strcasecmp(optarg,"imap") == 0)
		ctl->server.protocol = P_IMAP;
#ifdef KERBEROS_V4
	    else if (strcasecmp(optarg,"imap-k4") == 0)
		ctl->server.protocol = P_IMAP_K4;
#endif /* KERBEROS_V4 */
#ifdef GSSAPI
	    else if (strcasecmp(optarg, "imap-gss") == 0)
                ctl->server.protocol = P_IMAP_GSS;
#endif /* GSSAPI */
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
#if INET6
	    ctl->server.service = optarg;
#else /* INET6 */
	    ctl->server.port = xatoi(optarg, &errflag);
#endif /* INET6 */
	    break;
	case 'A':
	case LA_AUTHENTICATE:
	    if (strcmp(optarg, "password") == 0)
		ctl->server.preauthenticate = A_PASSWORD;
	    else if (strcmp(optarg, "kerberos") == 0)
#ifdef KERBEROS_V5
		ctl->server.preauthenticate = A_KERBEROS_V5;
	    else if (strcmp(optarg, "kerberos_v5") == 0)
		ctl->server.preauthenticate = A_KERBEROS_V5;
#else
		ctl->server.preauthenticate = A_KERBEROS_V4;
	    else if (strcmp(optarg, "kerberos_v4") == 0)
		ctl->server.preauthenticate = A_KERBEROS_V4;
#endif /* KERBEROS_V5 */
	    else {
		fprintf(stderr,"Invalid preauthentication `%s' specified.\n", optarg);
		errflag++;
	    }
	    break;
	case 't':
	case LA_TIMEOUT:
	    ctl->server.timeout = xatoi(optarg, &errflag);
	    if (ctl->server.timeout == 0)
		ctl->server.timeout = -1;
	    break;
	case 'E':
	case LA_ENVELOPE:
	    ctl->server.envelope = xstrdup(optarg);
	    break;
	case 'Q':    
	case LA_QVIRTUAL:
	    ctl->server.qvirtual = xstrdup(optarg);
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
	case LA_NOKEEP:
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
	    c = xatoi(optarg, &errflag);
	    ctl->limit = NUM_VALUE(c);
	    break;
	case 'r':
	case LA_FOLDER:
	    buf = xmalloc(strlen(optarg));
	    strcpy(buf, optarg);
	    cp = strtok(buf, ",");
	    do {
		save_str(&ctl->mailboxes, cp, 0);
	    } while
		((cp = strtok((char *)NULL, ",")));
	    free(buf);
	    break;
	case 'S':
	case LA_SMTPHOST:
	    buf = xmalloc(strlen(optarg));
	    strcpy(buf, optarg);
	    cp = strtok(buf, ",");
	    do {
		save_str(&ctl->smtphunt, cp, TRUE);
	    } while
		((cp = strtok((char *)NULL, ",")));
	    ocount++;
	    free(buf);
	    break;
	case 'D':
	case LA_SMTPADDR:
	    ctl->smtpaddress = xstrdup(optarg);
	    break;
	case 'Z':
	case LA_ANTISPAM:
	    buf = xmalloc(strlen(optarg));
	    strcpy(buf, optarg);
	    cp = strtok(buf, ",");
	    do {
		struct idlist	*idp = save_str(&ctl->antispam, NULL, 0);;

		idp->val.status.num = atoi(cp);
	    } while
		((cp = strtok((char *)NULL, ",")));
	    free(buf);
	    break;
	case 'b':
	case LA_BATCHLIMIT:
	    c = xatoi(optarg, &errflag);
	    ctl->batchlimit = NUM_VALUE(c);
	    break;
	case 'B':
	case LA_FETCHLIMIT:
	    c = xatoi(optarg, &errflag);
	    ctl->fetchlimit = NUM_VALUE(c);
	    break;
	case 'e':
	case LA_EXPUNGE:
	    c = xatoi(optarg, &errflag);
	    ctl->expunge = NUM_VALUE(c);
	    break;
	case 'm':
	case LA_MDA:
	    ctl->mda = xstrdup(optarg);
	    ocount++;
	    break;

	case 'T':
	case LA_NETSEC:
#if NET_SECURITY
	    ctl->server.netsec = (void *)optarg;
#else
	    fprintf(stderr, "fetchmail: network security support is disabled\n");
	    errflag++;
#endif /* NET_SECURITY */
	    break;

#if defined(linux) && !INET6
	case 'I':
	case LA_INTERFACE:
	    interface_parse(optarg, &ctl->server);
	    break;
	case 'M':
	case LA_MONITOR:
	    ctl->server.monitor = xstrdup(optarg);
	    break;
#endif /* defined(linux) && !INET6 */

	case 'y':
	case LA_YYDEBUG:
	    yydebug = TRUE;
	    break;

	case LA_CONFIGDUMP:
	    configdump = TRUE;
	    break;

	case LA_SYSLOG:
	    rctl->use_syslog = FLAG_TRUE;
	    break;

	case LA_NOSYSLOG:
	    rctl->use_syslog = FLAG_FALSE;
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
	fputs("      --invisible   suppress Received line & enable host spoofing\n", stderr);
	fputs("  -f, --fetchmailrc specify alternate run control file\n", stderr);
	fputs("  -i, --idfile      specify alternate UIDs file\n", stderr);
	fputs("      --postmaster  specify recipient of last resort\n",stderr);
#if defined(linux) && !INET6
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
	fputs("  -Q, --qvirtual    prefix to remove from local user id\n",stderr);

	fputs("  -u, --username    specify users's login on server\n", stderr);
	fputs("  -a, --all         retrieve old and new messages\n", stderr);
	fputs("  -K, --nokeep      delete new messages after retrieval\n", stderr);
	fputs("  -k, --keep        save new messages after retrieval\n", stderr);
	fputs("  -F, --flush       delete old messages from server\n", stderr);
	fputs("  -n, --norewrite   don't rewrite header addresses\n", stderr);
	fputs("  -l, --limit       don't fetch messages over given size\n", stderr);

#if NET_SECURITY
	fputs("  -T, --netsec      set IP security request\n", stderr);
#endif /* NET_SECURITY */
	fputs("  -S, --smtphost    set SMTP forwarding host\n", stderr);
	fputs("  -D, --smtpaddress set SMTP delivery domain to use\n", stderr);
	fputs("  -Z, --antispam,   set antispam response values\n", stderr);
	fputs("  -b, --batchlimit  set batch limit for SMTP connections\n", stderr);
	fputs("  -B, --fetchlimit  set fetch limit for server connections\n", stderr);
	fputs("  -e, --expunge     set max deletions between expunges\n", stderr);
	fputs("  -r, --folder      specify remote folder name\n", stderr);
	return(-1);
    }

    return(optind);
}

/* options.c ends here */
