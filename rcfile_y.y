%{
/*
 * rcfile_y.y -- Run control file parser for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
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

struct query cmd_opts;	/* where to put command-line info */
struct query *querylist;	/* head of server list (globally visible) */

int yydebug;	/* in case we didn't generate with -- debug */

static struct query current;		/* current server record */
static int prc_errflag;

static void record_current();
static void user_reset();
static int reset_server(char *name, int skip);

/* using Bison, this arranges that yydebug messages will show actual tokens */
extern char * yytext;
#define YYPRINT(fp, type, val)	fprintf(fp, " = \"%s\"", yytext)
%}

%union {
  int proto;
  int number;
  char *sval;
}

%token DEFAULTS POLL SKIP AKA LOCALDOMAINS PROTOCOL
%token AUTHENTICATE TIMEOUT KPOP KERBEROS4
%token ENVELOPE USERNAME PASSWORD FOLDER SMTPHOST MDA PRECONNECT LIMIT
%token IS HERE THERE TO MAP WILDCARD
%token SET BATCHLIMIT FETCHLIMIT LOGFILE DAEMON SYSLOG INTERFACE MONITOR
%token <proto> PROTO
%token <sval>  STRING
%token <number> NUMBER
%token NO KEEP FLUSH FETCHALL REWRITE FORCECR STRIPCR DNS PORT UIDL INTERVAL

%%

rcfile		: /* empty */
		| statement_list
		;

statement_list	: statement
		| statement_list statement
		;

/* future global options should also have the form SET <name> <value> */
statement	: SET LOGFILE MAP STRING	{logfile = xstrdup($4);}
		| SET DAEMON NUMBER		{poll_interval = $3;}
		| SET SYSLOG			{use_syslog = TRUE;}

/* 
 * The way the next two productions are written depends on the fact that
 * userspecs cannot be empty.  It's a kluge to deal with files that set
 * up a load of defaults and then have poll statements following with no
 * user options at all. 
 */
		| define_server serverspecs		{record_current();}
		| define_server serverspecs userspecs
		;

define_server	: POLL STRING	{
    				    if (!reset_server($2, FALSE))
				    {
					yyerror("duplicate entry name not allowed");
					YYERROR;
				    }
				}
		| SKIP STRING	{
    				    if (!reset_server($2, TRUE))
				    {
					yyerror("duplicate entry name not allowed");
					YYERROR;
				    }
				}
		| DEFAULTS	{
    				    if (!reset_server("defaults", FALSE))
				    {
					yyerror("can't have two default entries");
					YYERROR;
				    }
				}
  		;

serverspecs	: /* EMPTY */
		| serverspecs serv_option
		;

alias_list	: STRING		{save_str(&current.server.names,-1,$1);}
		| alias_list STRING	{save_str(&current.server.names,-1,$2);}
		;

domain_list	: STRING		{save_str(&current.server.localdomains,-1,$1);}
		| domain_list STRING	{save_str(&current.server.localdomains,-1,$2);}
		;

serv_option	: AKA alias_list
		| LOCALDOMAINS domain_list
		| PROTOCOL PROTO	{current.server.protocol = $2;}
		| PROTOCOL KPOP		{
					    current.server.protocol = P_POP3;
		    			    current.server.authenticate = A_KERBEROS_V4;
					    current.server.port = KPOP_PORT;
					}
		| UIDL			{current.server.uidl = FLAG_TRUE;}
		| NO UIDL		{current.server.uidl  = FLAG_FALSE;}
		| PORT NUMBER		{current.server.port = $2;}
		| INTERVAL NUMBER		{current.server.interval = $2;}
		| AUTHENTICATE PASSWORD	{current.server.authenticate = A_PASSWORD;}
		| AUTHENTICATE KERBEROS4	{current.server.authenticate = A_KERBEROS_V4;}
		| TIMEOUT NUMBER	{current.server.timeout = $2;}
		| ENVELOPE STRING	{current.server.envelope = xstrdup($2);}
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

/*
 * The first and only the first user spec may omit the USERNAME part.
 * This is a backward-compatibility kluge to allow old popclient files
 * to keep working.
 */
userspecs	: user1opts		{record_current(); user_reset();}
		| user1opts explicits	
					{
						record_current(); user_reset();
	fprintf(stderr, "Warning: user entry with no `user' keyword\n");
					}
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

smtp_list	: STRING		{save_str(&current.smtphunt, -1, $1);}
		| smtp_list STRING	{save_str(&current.smtphunt, -1, $2);}
		;

user_option	: TO localnames HERE
		| TO localnames
		| IS localnames HERE
		| IS localnames

		| IS STRING THERE	{current.remotename = xstrdup($2);}
		| PASSWORD STRING	{current.password   = xstrdup($2);}
		| FOLDER folder_list
		| SMTPHOST smtp_list
		| MDA STRING		{current.mda        = xstrdup($2);}
		| PRECONNECT STRING	{current.preconnect = xstrdup($2);}

		| KEEP			{current.keep       = FLAG_TRUE;}
		| FLUSH			{current.flush      = FLAG_TRUE;}
		| FETCHALL		{current.fetchall   = FLAG_TRUE;}
		| REWRITE		{current.rewrite    = FLAG_TRUE;}
		| FORCECR		{current.forcecr    = FLAG_TRUE;}
		| STRIPCR		{current.stripcr    = FLAG_TRUE;}

		| NO KEEP		{current.keep       = FLAG_FALSE;}
		| NO FLUSH		{current.flush      = FLAG_FALSE;}
		| NO FETCHALL		{current.fetchall   = FLAG_FALSE;}
		| NO REWRITE		{current.rewrite    = FLAG_FALSE;}
		| NO FORCECR		{current.forcecr    = FLAG_FALSE;}
		| NO STRIPCR		{current.stripcr    = FLAG_FALSE;}

		| LIMIT NUMBER		{current.limit      = $2;}
		| FETCHLIMIT NUMBER	{current.fetchlimit = $2;}
		| BATCHLIMIT NUMBER	{current.batchlimit = $2;}
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
    if (strcmp("/dev/null", pathname) == 0 || versioninfo)
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

int prc_parse_file (pathname)
/* digest the configuration into a linked list of host records */
const char *pathname;		/* pathname for the configuration file */
{
    prc_errflag = 0;
    querylist = hosttail = (struct query *)NULL;

    /* Check that the file is secure */
    if ((prc_errflag = prc_filecheck(pathname)) != 0)
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

static int reset_server(char *name, int skip)
/* clear the entire global record and initialize it with a new name */
{
    struct query *ctl;

    /* don't allow name collisions, this screws up the data structures */
    for (ctl = querylist; ctl; ctl = ctl->next)
	if (strcmp(name, ctl->server.names->id) == 0)
	    return(FALSE);

    memset(&current,'\0',sizeof(current));
    current.smtp_socket = -1;
    save_str(&current.server.names, -1, name);
    current.server.skip = skip;
    return(TRUE);
}


static void user_reset(void)
/* clear the global current record (server parameters) used by the parser */
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
    return(node);
}

static void record_current(void)
/* register current parameters and append to the host list */
{
#define FLAG_FORCE(fld) if (cmd_opts.fld) current.fld = cmd_opts.fld
    FLAG_FORCE(server.protocol);
    FLAG_FORCE(server.port);
    FLAG_FORCE(server.interval);
    FLAG_FORCE(server.authenticate);
    FLAG_FORCE(server.timeout);
    FLAG_FORCE(server.envelope);
    FLAG_FORCE(server.skip);
    FLAG_FORCE(server.dns);

#ifdef linux
    FLAG_FORCE(server.interface);
    FLAG_FORCE(server.monitor);
    FLAG_FORCE(server.interface_pair);
#endif /* linux */

    FLAG_FORCE(remotename);
    FLAG_FORCE(password);
    if (cmd_opts.mailboxes)
	save_str(&current.mailboxes, -1, cmd_opts.mailboxes->id);
    if (cmd_opts.smtphunt)
	save_str(&current.smtphunt, -1, cmd_opts.smtphunt->id);
    FLAG_FORCE(mda);
    FLAG_FORCE(preconnect);

    FLAG_FORCE(keep);
    FLAG_FORCE(flush);
    FLAG_FORCE(fetchall);
    FLAG_FORCE(rewrite);
    FLAG_FORCE(forcecr);
    FLAG_FORCE(stripcr);
    FLAG_FORCE(limit);
    FLAG_FORCE(fetchlimit);
    FLAG_FORCE(batchlimit);

#undef FLAG_FORCE

    (void) hostalloc(&current);
}

void optmerge(struct query *h2, struct query *h1)
/* merge two options records; empty fields in h2 are filled in from h1 */
{
    append_str_list(&h2->server.localdomains, &h1->server.localdomains);
    append_str_list(&h2->localnames, &h1->localnames);
    append_str_list(&h2->mailboxes, &h1->mailboxes);
    append_str_list(&h2->smtphunt, &h1->smtphunt);

#define FLAG_MERGE(fld) if (!h2->fld) h2->fld = h1->fld
    FLAG_MERGE(server.protocol);
    FLAG_MERGE(server.port);
    FLAG_MERGE(server.interval);
    FLAG_MERGE(server.authenticate);
    FLAG_MERGE(server.timeout);
    FLAG_MERGE(server.envelope);
    FLAG_MERGE(server.skip);
    FLAG_MERGE(server.dns);

#ifdef linux
    FLAG_MERGE(server.interface);
    FLAG_MERGE(server.monitor);
    FLAG_MERGE(server.interface_pair);
#endif /* linux */

    FLAG_MERGE(remotename);
    FLAG_MERGE(password);
    FLAG_MERGE(mda);
    FLAG_MERGE(preconnect);

    FLAG_MERGE(keep);
    FLAG_MERGE(flush);
    FLAG_MERGE(fetchall);
    FLAG_MERGE(rewrite);
    FLAG_MERGE(forcecr);
    FLAG_MERGE(stripcr);
    FLAG_MERGE(limit);
    FLAG_MERGE(fetchlimit);
    FLAG_MERGE(batchlimit);
#undef FLAG_MERGE
}

/* easier to do this than cope with variations in where the library lives */
int yywrap(void) {return 1;}

/* rcfile_y.y ends here */
