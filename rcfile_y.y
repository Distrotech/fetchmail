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
#include "fetchmail.h"

struct hostrec cmd_opts;	/* where to put command-line info */
struct hostrec *hostlist;	/* head of server list (globally visible) */

int yydebug;	/* in case we didn't generate with -- debug */

static struct hostrec current;		/* current server record */
static int prc_errflag;
%}

%union {
  int proto;
  int flag;
  int number;
  char *sval;
}

%token DEFAULTS SERVER PROTOCOL AUTHENTICATE TIMEOUT KPOP KERBEROS
%token USERNAME PASSWORD FOLDER SMTPHOST MDA IS HERE THERE TO
%token <proto> PROTO
%token <sval>  STRING
%token <number> NUMBER
%token <flag>  KEEP FLUSH FETCHALL REWRITE PORT SKIP

/* these are actually used by the lexer */
%token FLAG_TRUE	2
%token FLAG_FALSE	1

%%

rcfile		: /* empty */
		| statement_list
		;

statement_list	: statement
		| statement_list statement
		;

statement	: define_server serverspecs userspecs      
		;

define_server	: SERVER STRING		{strcpy(current.servername, $2);}
		| SKIP SERVER STRING	{strcpy(current.servername, $3);
						current.skip=($1==FLAG_TRUE);}
		| DEFAULTS	{strcpy(current.servername,"defaults");}
  		;

serverspecs	: /* EMPTY */
		| serverspecs serv_option
		;

serv_option	: PROTOCOL PROTO	{current.protocol = $2;}
		| PROTOCOL KPOP		{
					    current.protocol = P_POP3;
		    			    current.authenticate = A_KERBEROS;
					    current.port = KPOP_PORT;
					}
		| PORT NUMBER		{current.port = $2;}
		| SKIP			{current.skip = ($1==FLAG_TRUE);}
		| AUTHENTICATE PASSWORD	{current.authenticate = A_PASSWORD;}
		| AUTHENTICATE KERBEROS	{current.authenticate = A_KERBEROS;}
		| TIMEOUT NUMBER	{current.timeout = $2;}
		;

/* the first and only the first user spec may omit the USERNAME part */
userspecs	: user1opts		{prc_register(); prc_reset();}
		| user1opts explicits	{prc_register(); prc_reset();}
		| explicits
		;

explicits	: explicitdef		{prc_register(); prc_reset();}
		| explicits explicitdef	{prc_register(); prc_reset();}
		;

explicitdef	: userdef user0opts
		;

userdef		: USERNAME STRING	{strcpy(current.remotename, $2);}
		| USERNAME STRING HERE	{strcpy(current.localname, $2);}
		| USERNAME STRING THERE	{strcpy(current.remotename, $2);}
		;

user0opts	: /* EMPTY */
		| user0opts user_option
		;

user1opts	: user_option
		| user1opts user_option
		;

user_option	: TO STRING		{strcpy(current.localname, $2);}
		| TO STRING HERE	{strcpy(current.localname, $2);}
		| IS STRING		{strcpy(current.localname, $2);}
		| IS STRING HERE	{strcpy(current.localname, $2);}
		| IS STRING THERE	{strcpy(current.remotename, $2);}
		| PASSWORD STRING	{strcpy(current.password, $2);}
		| FOLDER STRING 	{strcpy(current.mailbox, $2);}
		| SMTPHOST STRING	{strcpy(current.smtphost, $2);}
		| MDA STRING		{strcpy(current.mda, $2);}

		| KEEP			{current.keep = ($1==FLAG_TRUE);}
		| FLUSH			{current.flush = ($1==FLAG_TRUE);}
		| FETCHALL		{current.fetchall = ($1==FLAG_TRUE);}
		| REWRITE		{current.norewrite = ($1==FLAG_TRUE);}
		;
%%

/* lexer interface */
extern char *rcfile;
extern int prc_lineno;
extern char *yytext;
extern FILE *yyin;

static struct hostrec *hosttail;	/* where to add new elements */

int yyerror (s)
/* report a syntax error */
char *s;	/* error string */
{
  fprintf(stderr,"%s line %d: %s at %s\n", rcfile, prc_lineno, s, yytext);
  prc_errflag++;
}

int prc_filecheck(pathname)
/* check that a configuration file is secure */
char *pathname;		/* pathname for the configuration file */
{
    struct stat statbuf;

    /* the run control file must have the same uid as the REAL uid of this 
       process, it must have permissions no greater than 600, and it must not 
       be a symbolic link.  We check these conditions here. */

    errno = 0;
    if (lstat(pathname, &statbuf) < 0) {
	if (errno == ENOENT) 
	    return(0);
	else {
	    perror(pathname);
	    return(PS_IOERR);
	}
    }

    if ((statbuf.st_mode & S_IFLNK) == S_IFLNK) {
	fprintf(stderr, "File %s must not be a symbolic link.\n", pathname);
	return(PS_AUTHFAIL);
    }

    if (statbuf.st_mode & ~(S_IFREG | S_IREAD | S_IWRITE)) {
	fprintf(stderr, "File %s must have no more than -rw------ permissions.\n", 
		pathname);
	return(PS_AUTHFAIL);
    }

    if (statbuf.st_uid != getuid()) {
	fprintf(stderr, "File %s must be owned by you.\n", pathname);
	return(PS_AUTHFAIL);
    }

    return(0);
}

prc_parse_file (pathname)
/* digest the configuration into a linked list of host records */
char *pathname;		/* pathname for the configuration file */
{
    prc_errflag = 0;
    hostlist = hosttail = (struct hostrec *)NULL;
    prc_reset();

    /* Check that the file is secure */
    if ((prc_errflag = prc_filecheck(pathname)) != 0)
	return(prc_errflag);

    if (errno == ENOENT)
	return(0);

    /* Open the configuration and feed it to the lexer. */
    if ((yyin = fopen(pathname,"r")) == (FILE *)NULL) {
	perror(pathname);
	return(PS_IOERR);
    }

    yyparse();		/* parse entire file */

    fclose(yyin);

    if (prc_errflag) 
	return(PS_SYNTAX);
    else
	return(0);
}

prc_reset()
/* clear the global current record (server parameters) used by the parser */
{
    char	savename[HOSTLEN+1];
    int		saveport, saveproto, saveauth;

    /*
     * Purpose of this code is to initialize the new server block with
     * the command-line data, but preserve whatever server name was
     * previously set.  Also preserve server options unless the
     * command-line explicitly overrides them.
     */
    (void) strcpy(savename, current.servername);
    saveport = current.port;
    saveproto = current.protocol;
    saveauth = current.authenticate;

    memset(&current, '\0', sizeof(current));

    (void) strcpy(current.servername, savename);
    current.protocol = saveproto;
    current.authenticate = saveauth;
}

struct hostrec *hostalloc(init)
/* append a host record to the host list */
struct hostrec *init;	/* pointer to block containing initial values */
{
    struct hostrec *node;

    /* allocate new node */
    node = (struct hostrec *) xmalloc(sizeof(struct hostrec));

    /* initialize it */
    memcpy(node, init, sizeof(struct hostrec));

    /* append to end of list */
    if (hosttail != (struct hostrec *) 0)
	hosttail->next = node;	/* list contains at least one element */
    else
	hostlist = node;	/* list is empty */
    hosttail = node;
    return(node);
}

int prc_register()
/* register current parameters and append to the host list */
{
#define STR_FORCE(fld, len) if (cmd_opts.fld[0]) \
    					strcpy(current.fld, cmd_opts.fld)
    STR_FORCE(localname, USERNAMELEN);
    STR_FORCE(remotename, USERNAMELEN);
    STR_FORCE(password, PASSWORDLEN);
    STR_FORCE(mailbox, FOLDERLEN);
    STR_FORCE(smtphost, HOSTLEN);
    STR_FORCE(mda, MDALEN);
#undef STR_FORCE
    
#define FLAG_FORCE(fld) if (cmd_opts.fld) current.fld = cmd_opts.fld
    FLAG_FORCE(protocol);
    FLAG_FORCE(keep);
    FLAG_FORCE(flush);
    FLAG_FORCE(fetchall);
    FLAG_FORCE(norewrite);
    FLAG_FORCE(skip);
    FLAG_FORCE(port);
    FLAG_FORCE(authenticate);
    FLAG_FORCE(timeout);
#undef FLAG_FORCE

    (void) hostalloc(&current);
}

void optmerge(h2, h1)
/* merge two options records; empty fields in h2 are filled in from h1 */
struct hostrec *h1;
struct hostrec *h2;
{
#define STR_MERGE(fld, len) if (*(h2->fld) == '\0') strcpy(h2->fld, h1->fld)
    STR_MERGE(localname, USERNAMELEN);
    STR_MERGE(remotename, USERNAMELEN);
    STR_MERGE(password, PASSWORDLEN);
    STR_MERGE(mailbox, FOLDERLEN);
    STR_MERGE(smtphost, HOSTLEN);
    STR_MERGE(mda, MDALEN);
#undef STR_MERGE

#define FLAG_MERGE(fld) if (!h2->fld) h2->fld = h1->fld
    FLAG_MERGE(protocol);
    FLAG_MERGE(keep);
    FLAG_MERGE(flush);
    FLAG_MERGE(fetchall);
    FLAG_MERGE(norewrite);
    FLAG_MERGE(skip);
    FLAG_MERGE(port);
    FLAG_MERGE(authenticate);
    FLAG_MERGE(timeout);
#undef FLAG_MERGE
}

/* easier to do this than cope with variations in where the library lives */
int yywrap() {return 1;}

/* rcfile_y.y ends here */
