%{
/*
 * rcfile_y.y -- Run control file parser for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <string.h>

#include "fetchmail.h"

/* parser reads these */
char *rcfile;			/* path name of rc file */
struct query cmd_opts;		/* where to put command-line info */

/* parser sets these */
int poll_interval;		/* poll interval in seconds */
char *logfile;			/* log file for daemon mode */
flag errors_to_syslog;		/* if syslog was set */
flag use_invisible;		/* if invisible was set */
struct query *querylist;	/* head of server list (globally visible) */

int yydebug;			/* in case we didn't generate with -- debug */

static struct query current;	/* current server record */
static int prc_errflag;
static struct hostdata *leadentry;
static flag trailer;

static void record_current();
static void user_reset();
static void reset_server(char *name, int skip);

/* using Bison, this arranges that yydebug messages will show actual tokens */
extern char * yytext;
#define YYPRINT(fp, type, val)	fprintf(fp, " = \"%s\"", yytext)
%}

%union {
  int proto;
  int number;
  char *sval;
}

%token DEFAULTS POLL SKIP VIA AKA LOCALDOMAINS PROTOCOL
%token AUTHENTICATE TIMEOUT KPOP KERBEROS4
%token ENVELOPE QVIRTUAL USERNAME PASSWORD FOLDER SMTPHOST MDA SMTPADDRESS
%token PRECONNECT POSTCONNECT LIMIT
%token IS HERE THERE TO MAP WILDCARD
%token BATCHLIMIT FETCHLIMIT EXPUNGE
%token SET LOGFILE DAEMON SYSLOG INVISIBLE INTERFACE MONITOR
%token <proto> PROTO
%token <sval>  STRING
%token <number> NUMBER
%token NO KEEP FLUSH FETCHALL REWRITE FORCECR STRIPCR PASS8BITS DROPSTATUS
%token DNS PORT UIDL INTERVAL

%%

rcfile		: /* empty */
		| statement_list
		;

statement_list	: statement
		| statement_list statement
		;

optmap		: MAP | /* EMPTY */;

/* future global options should also have the form SET <name> optmap <value> */
statement	: SET LOGFILE optmap STRING	{logfile = xstrdup($4);}
		| SET DAEMON optmap NUMBER	{poll_interval = $4;}
		| SET SYSLOG			{errors_to_syslog = TRUE;}
		| SET INVISIBLE			{use_invisible = TRUE;}

/* 
 * The way the next two productions are written depends on the fact that
 * userspecs cannot be empty.  It's a kluge to deal with files that set
 * up a load of defaults and then have poll statements following with no
 * user options at all. 
 */
		| define_server serverspecs		{record_current();}
		| define_server serverspecs userspecs

/* detect and complain about the most common user error */
		| define_server serverspecs userspecs serv_option
			{yyerror("server option after user options");}
		;

define_server	: POLL STRING		{reset_server($2, FALSE);}
		| SKIP STRING		{reset_server($2, TRUE);}
		| DEFAULTS		{reset_server("defaults", FALSE);}
  		;

serverspecs	: /* EMPTY */
		| serverspecs serv_option
		;

alias_list	: STRING		{save_str(&current.server.akalist,-1,$1);}
		| alias_list STRING	{save_str(&current.server.akalist,-1,$2);}
		;

domain_list	: STRING		{save_str(&current.server.localdomains,-1,$1);}
		| domain_list STRING	{save_str(&current.server.localdomains,-1,$2);}
		;

serv_option	: AKA alias_list
		| VIA STRING		{current.server.via = xstrdup($2);}
		| LOCALDOMAINS domain_list
		| PROTOCOL PROTO	{current.server.protocol = $2;}
		| PROTOCOL KPOP		{
					    current.server.protocol = P_POP3;
		    			    current.server.preauthenticate = A_KERBEROS_V4;
					    current.server.port = KPOP_PORT;
					}
		| UIDL			{current.server.uidl = FLAG_TRUE;}
		| NO UIDL		{current.server.uidl  = FLAG_FALSE;}
		| PORT NUMBER		{current.server.port = $2;}
		| INTERVAL NUMBER		{current.server.interval = $2;}
		| AUTHENTICATE PASSWORD	{current.server.preauthenticate = A_PASSWORD;}
		| AUTHENTICATE KERBEROS4	{current.server.preauthenticate = A_KERBEROS_V4;}
		| TIMEOUT NUMBER	{current.server.timeout = $2;}

		| ENVELOPE NUMBER STRING 
					{
					    current.server.envelope = 
						xstrdup($3);
					    current.server.envskip = $2;
					}
		| ENVELOPE STRING
					{
					    current.server.envelope = 
						xstrdup($2);
					    current.server.envskip = 0;
					}

		| QVIRTUAL STRING	{current.server.qvirtual = xstrdup($2);}
		| INTERFACE STRING	{
#ifdef linux
					interface_parse($2, &current.server);
#else
					fprintf(stderr, "fetchmail: interface option is only supported under Linux\n");
#endif /* linux */
					}
		| MONITOR STRING	{
#ifdef linux
					current.server.monitor = xstrdup($2);
#else
					fprintf(stderr, "fetchmail: monitor option is only supported under Linux\n");
#endif /* linux */
					}
		| DNS			{current.server.dns = FLAG_TRUE;}
		| NO DNS		{current.server.dns = FLAG_FALSE;}
		| NO ENVELOPE		{current.server.envelope = STRING_DISABLED;}
		;

userspecs	: user1opts		{record_current(); user_reset();}
		| explicits
		;

explicits	: explicitdef		{record_current(); user_reset();}
		| explicits explicitdef	{record_current(); user_reset();}
		;

explicitdef	: userdef user0opts
		;

userdef		: USERNAME STRING	{current.remotename = xstrdup($2);}
		| USERNAME mapping_list HERE
		| USERNAME STRING THERE	{current.remotename = xstrdup($2);}
		;

user0opts	: /* EMPTY */
		| user0opts user_option
		;

user1opts	: user_option
		| user1opts user_option
		;

localnames	: WILDCARD		{current.wildcard =  TRUE;}
		| mapping_list		{current.wildcard =  FALSE;}
		| mapping_list WILDCARD	{current.wildcard =  TRUE;}
		;

mapping_list	: mapping		
		| mapping_list mapping
		;

mapping		: STRING	
				{save_str_pair(&current.localnames, $1, NULL);}
		| STRING MAP STRING
				{save_str_pair(&current.localnames, $1, $3);}
		;

folder_list	: STRING		{save_str(&current.mailboxes,-1,$1);}
		| folder_list STRING	{save_str(&current.mailboxes,-1,$2);}
		;

smtp_list	: STRING		{save_str(&current.smtphunt, TRUE,$1);}
		| smtp_list STRING	{save_str(&current.smtphunt, TRUE,$2);}
		;

user_option	: TO localnames HERE
		| TO localnames
		| IS localnames HERE
		| IS localnames

		| IS STRING THERE	{current.remotename = xstrdup($2);}
		| PASSWORD STRING	{current.password   = xstrdup($2);}
		| FOLDER folder_list
		| SMTPHOST smtp_list
		| SMTPADDRESS STRING	{current.smtpaddress = xstrdup($2);}
		| MDA STRING		{current.mda        = xstrdup($2);}
		| PRECONNECT STRING	{current.preconnect = xstrdup($2);}
		| POSTCONNECT STRING	{current.postconnect = xstrdup($2);}

		| KEEP			{current.keep       = FLAG_TRUE;}
		| FLUSH			{current.flush      = FLAG_TRUE;}
		| FETCHALL		{current.fetchall   = FLAG_TRUE;}
		| REWRITE		{current.rewrite    = FLAG_TRUE;}
		| FORCECR		{current.forcecr    = FLAG_TRUE;}
		| STRIPCR		{current.stripcr    = FLAG_TRUE;}
		| PASS8BITS		{current.pass8bits  = FLAG_TRUE;}
		| DROPSTATUS		{current.dropstatus = FLAG_TRUE;}

		| NO KEEP		{current.keep       = FLAG_FALSE;}
		| NO FLUSH		{current.flush      = FLAG_FALSE;}
		| NO FETCHALL		{current.fetchall   = FLAG_FALSE;}
		| NO REWRITE		{current.rewrite    = FLAG_FALSE;}
		| NO FORCECR		{current.forcecr    = FLAG_FALSE;}
		| NO STRIPCR		{current.stripcr    = FLAG_FALSE;}
		| NO PASS8BITS		{current.pass8bits  = FLAG_FALSE;}
		| NO DROPSTATUS		{current.dropstatus = FLAG_FALSE;}

		| LIMIT NUMBER		{current.limit      = NUM_VALUE($2);}
		| FETCHLIMIT NUMBER	{current.fetchlimit = NUM_VALUE($2);}
		| BATCHLIMIT NUMBER	{current.batchlimit = NUM_VALUE($2);}
		| EXPUNGE NUMBER	{current.expunge    = NUM_VALUE($2);}
		;
%%

/* lexer interface */
extern char *rcfile;
extern int prc_lineno;
extern char *yytext;
extern FILE *yyin;

static struct query *hosttail;	/* where to add new elements */

void yyerror (const char *s)
/* report a syntax error */
{
    error_at_line( 0, 0, rcfile, prc_lineno, "%s at %s", s, 
		   (yytext && yytext[0]) ? yytext : "end of input");
    prc_errflag++;
}

int prc_filecheck(pathname)
/* check that a configuration file is secure */
const char *pathname;		/* pathname for the configuration file */
{
    struct stat statbuf;

    errno = 0;

    /* special cases useful for debugging purposes */
    if (strcmp("/dev/null", pathname) == 0)
	return(0);

    /* the run control file must have the same uid as the REAL uid of this 
       process, it must have permissions no greater than 600, and it must not 
       be a symbolic link.  We check these conditions here. */

    if (lstat(pathname, &statbuf) < 0) {
	if (errno == ENOENT) 
	    return(0);
	else {
	    error(0, errno, "lstat: %s", pathname);
	    return(PS_IOERR);
	}
    }

    if ((statbuf.st_mode & S_IFLNK) == S_IFLNK) {
	fprintf(stderr, "File %s must not be a symbolic link.\n", pathname);
	return(PS_AUTHFAIL);
    }

    if (statbuf.st_mode & ~(S_IFREG | S_IREAD | S_IWRITE)) {
	fprintf(stderr, "File %s must have no more than -rw------ (0600) permissions.\n", 
		pathname);
	return(PS_AUTHFAIL);
    }

    if (statbuf.st_uid != getuid()) {
	fprintf(stderr, "File %s must be owned by you.\n", pathname);
	return(PS_AUTHFAIL);
    }

    return(0);
}

int prc_parse_file (const char *pathname, const flag securecheck)
/* digest the configuration into a linked list of host records */
{
    prc_errflag = 0;
    querylist = hosttail = (struct query *)NULL;

    errno = 0;

    /* Check that the file is secure */
    if (securecheck && (prc_errflag = prc_filecheck(pathname)) != 0)
	return(prc_errflag);

    if (errno == ENOENT)
	return(0);

    /* Open the configuration and feed it to the lexer. */
    if ((yyin = fopen(pathname,"r")) == (FILE *)NULL) {
	error(0, errno, "open: %s", pathname);
	return(PS_IOERR);
    }

    yyparse();		/* parse entire file */

    fclose(yyin);

    if (prc_errflag) 
	return(PS_SYNTAX);
    else
	return(0);
}

static void reset_server(char *name, int skip)
/* clear the entire global record and initialize it with a new name */
{
    trailer = FALSE;
    memset(&current,'\0',sizeof(current));
    current.smtp_socket = -1;
    current.server.pollname = xstrdup(name);
    current.server.skip = skip;
}


static void user_reset(void)
/* clear the global current record (user parameters) used by the parser */
{
    struct hostdata save;

    /*
     * Purpose of this code is to initialize the new server block, but
     * preserve whatever server name was previously set.  Also
     * preserve server options unless the command-line explicitly
     * overrides them.
     */
    save = current.server;

    memset(&current, '\0', sizeof(current));
    current.smtp_socket = -1;

    current.server = save;
}

struct query *hostalloc(init)
/* append a host record to the host list */
struct query *init;	/* pointer to block containing initial values */
{
    struct query *node;

    /* allocate new node */
    node = (struct query *) xmalloc(sizeof(struct query));

    /* initialize it */
    memcpy(node, init, sizeof(struct query));

    /* append to end of list */
    if (hosttail != (struct query *) 0)
	hosttail->next = node;	/* list contains at least one element */
    else
	querylist = node;	/* list is empty */
    hosttail = node;

    if (trailer)
	node->server.lead_server = leadentry;
    else
    {
	node->server.lead_server = NULL;
	leadentry = &node->server;
    }

    return(node);
}

static void record_current(void)
/* register current parameters and append to the host list */
{
#define FLAG_FORCE(fld) if (cmd_opts.fld) current.fld = cmd_opts.fld
    FLAG_FORCE(server.via);
    FLAG_FORCE(server.protocol);
    FLAG_FORCE(server.port);
    FLAG_FORCE(server.interval);
    FLAG_FORCE(server.preauthenticate);
    FLAG_FORCE(server.timeout);
    FLAG_FORCE(server.envelope);
    FLAG_FORCE(server.envskip);
    FLAG_FORCE(server.qvirtual);
    FLAG_FORCE(server.skip);
    FLAG_FORCE(server.dns);
    FLAG_FORCE(server.uidl);

#ifdef linux
    FLAG_FORCE(server.interface);
    FLAG_FORCE(server.monitor);
    FLAG_FORCE(server.interface_pair);
#endif /* linux */

    FLAG_FORCE(remotename);
    FLAG_FORCE(password);
    if (cmd_opts.mailboxes)
	current.mailboxes = cmd_opts.mailboxes;
    if (cmd_opts.smtphunt)
	current.smtphunt = cmd_opts.smtphunt;
    FLAG_FORCE(mda);
	FLAG_FORCE(smtpaddress);
    FLAG_FORCE(preconnect);
    FLAG_FORCE(postconnect);

    FLAG_FORCE(keep);
    FLAG_FORCE(flush);
    FLAG_FORCE(fetchall);
    FLAG_FORCE(rewrite);
    FLAG_FORCE(forcecr);
    FLAG_FORCE(stripcr);
    FLAG_FORCE(pass8bits);
    FLAG_FORCE(dropstatus);
    FLAG_FORCE(limit);
    FLAG_FORCE(fetchlimit);
    FLAG_FORCE(batchlimit);
    FLAG_FORCE(expunge);

#undef FLAG_FORCE

    (void) hostalloc(&current);

    trailer = TRUE;
}

void optmerge(struct query *h2, struct query *h1)
/* merge two options records; empty fields in h2 are filled in from h1 */
{
    append_str_list(&h2->server.localdomains, &h1->server.localdomains);
    append_str_list(&h2->localnames, &h1->localnames);
    append_str_list(&h2->mailboxes, &h1->mailboxes);
    append_str_list(&h2->smtphunt, &h1->smtphunt);

#define FLAG_MERGE(fld) if (!h2->fld) h2->fld = h1->fld
    FLAG_MERGE(server.via);
    FLAG_MERGE(server.protocol);
    FLAG_MERGE(server.port);
    FLAG_MERGE(server.interval);
    FLAG_MERGE(server.preauthenticate);
    FLAG_MERGE(server.timeout);
    FLAG_MERGE(server.envelope);
    FLAG_MERGE(server.envskip);
    FLAG_MERGE(server.qvirtual);
    FLAG_MERGE(server.skip);
    FLAG_MERGE(server.dns);
    FLAG_MERGE(server.uidl);

#ifdef linux
    FLAG_MERGE(server.interface);
    FLAG_MERGE(server.monitor);
    FLAG_MERGE(server.interface_pair);
#endif /* linux */

    FLAG_MERGE(remotename);
    FLAG_MERGE(password);
    FLAG_MERGE(mda);
    FLAG_MERGE(smtpaddress);
    FLAG_MERGE(preconnect);

    FLAG_MERGE(keep);
    FLAG_MERGE(flush);
    FLAG_MERGE(fetchall);
    FLAG_MERGE(rewrite);
    FLAG_MERGE(forcecr);
    FLAG_MERGE(stripcr);
    FLAG_MERGE(pass8bits);
    FLAG_MERGE(dropstatus);
    FLAG_MERGE(limit);
    FLAG_MERGE(fetchlimit);
    FLAG_MERGE(batchlimit);
    FLAG_MERGE(expunge);
#undef FLAG_MERGE
}

/* easier to do this than cope with variations in where the library lives */
int yywrap(void) {return 1;}

/* rcfile_y.y ends here */
