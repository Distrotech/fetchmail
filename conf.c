/*
 * conf.c -- main driver module for fetchmailconf
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include "tunable.h"

#include <stdio.h>
#include <ctype.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <string.h>
#include <pwd.h>
#include <errno.h>

#include "fetchmail.h"

/*
 * Note: this function dumps the entire configuration,
 * after merging of the defaults record (if any).  It
 * is intended to produce output parseable by a configuration
 * front end, not anything especially comfortable for humans.
 */

void dump_config(struct runctl *runp, struct query *querylist)
/* dump the in-core configuration in recompilable form */
{
    struct query *ctl;
    struct idlist *idp;
    time_t now;

    /* now write the edited configuration back to the file */
    time(&now);
    fprintf(stdout, "# fetchmail rc file generated at %s", ctime(&now));

    if (runp->poll_interval)
	fprintf(stdout, "set daemon %d\n", runp->poll_interval);
    if (runp->use_syslog)
	fprintf(stdout, "set syslog\n");
    if (runp->logfile)
	fprintf(stdout, "set logfile %s\n", runp->logfile);
    if (runp->idfile)
	fprintf(stdout, "set idfile %s\n", runp->idfile);
    if (runp->invisible)
	fprintf(stdout, "set invisible\n");

    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	/*
	 * First, the server stuff.
	 */
	if (!ctl->server.lead_server)
	{
	    flag using_kpop =
		(ctl->server.protocol == P_POP3 &&
		 ctl->server.port == KPOP_PORT &&
		 ctl->server.preauthenticate == A_KERBEROS_V4);

	    if (strcmp(ctl->server.pollname, "defaults") == 0)
		fputs("defaults ", stdout);
	    else
		fprintf(stdout, "%s %s ",
		    ctl->server.skip ? "skip" : "poll",
		    visbuf(ctl->server.pollname));
	    if (ctl->server.via)
		fprintf(stdout, "via %s ", ctl->server.via);
	    if (ctl->server.protocol != P_AUTO)
		fprintf(stdout, "with protocol %s ",
			using_kpop ? "KPOP" : showproto(ctl->server.protocol));
	    if (ctl->server.port)
		fprintf(stdout, "port %d ", ctl->server.port);
	    if (ctl->server.timeout)
		fprintf(stdout, "timeout %d ", ctl->server.timeout);
	    if (ctl->server.interval)
		fprintf(stdout, "interval %d ", ctl->server.interval);
	    if (ctl->server.envelope == STRING_DISABLED)
		fprintf(stdout, "no envelope ");
	    else if (ctl->server.envelope)
		fprintf(stdout, "envelope \"%s\" ", visbuf(ctl->server.envelope));
	    if (ctl->server.qvirtual)
		fprintf(stdout, "qvirtual \"%s\" ", visbuf(ctl->server.qvirtual));
	    if (ctl->server.preauthenticate == A_KERBEROS_V4)
		fprintf(stdout, "auth kerberos_v4 ");
#define DUMPOPT(flag, str) \
		if (flag) \
		    fprintf(stdout, "%s ", str); \
		else \
		    fprintf(stdout, "no %s ", str);
#if defined(HAVE_GETHOSTBYNAME) && defined(HAVE_RES_SEARCH)
	    if (ctl->server.dns || ctl->server.uidl)
#else
	    if (ctl->server.uidl)
#endif /* HAVE_GETHOSTBYNAME && HAVE_RES_SEARCH */
		fputs("and options ", stdout);
#if defined(HAVE_GETHOSTBYNAME) && defined(HAVE_RES_SEARCH)
	    DUMPOPT(ctl->server.dns,  "dns");
#endif /* HAVE_GETHOSTBYNAME && HAVE_RES_SEARCH */
	    DUMPOPT(ctl->server.uidl, "uidl");
	    fputs("\n", stdout);

	    /* AKA and loca-domain declarations */
	    if (ctl->server.akalist || ctl->server.localdomains)
	    {
		fputc('\t', stdout);
		if (ctl->server.akalist)
		{
		    struct idlist *idp;

		    fprintf(stdout, "aka");
		    for (idp = ctl->server.akalist; idp; idp = idp->next)
			fprintf(stdout, " %s", visbuf(idp->id));
		}

		if (ctl->server.akalist && ctl->server.localdomains)
		    putc(' ', stdout);

		if (ctl->server.localdomains)
		{
		    struct idlist *idp;

		    fprintf(stdout, "localdomains");
		    for (idp = ctl->server.localdomains; idp; idp = idp->next)
			fprintf(stdout, " %s", visbuf(idp->id));
		}
		putc('\n', stdout);
	    }

#ifdef linux
	    if (ctl->server.monitor || ctl->server.interface)
	    {
		putc('\t', stdout);
		if (ctl->server.monitor)
		    fprintf(stdout, "monitor \"%s\" ", ctl->server.monitor);
		if (ctl->server.interface)
		    fprintf(stdout, "interface \"%s\"", ctl->server.interface);
		putc('\n', stdout);
	    }
#endif /* linux */
	}

	fputc('\t', stdout);
	if (ctl->remotename || ctl->password || ctl->localnames)
	{
	    if (ctl->remotename)
		fprintf(stdout, "user \"%s\" ", visbuf(ctl->remotename));
	    if (ctl->remotename && ctl->password)
		fputs("with ", stdout);
	    if (ctl->password)
		fprintf(stdout, "password \"%s\" ", visbuf(ctl->password));
	    if (ctl->localnames)
	    {
		fprintf(stdout, "is ");
		for (idp = ctl->localnames; idp; idp = idp->next)
		    if (idp->val.id2)
			fprintf(stdout, "\"%s\"=\"%s\" ", 
				visbuf(idp->id), visbuf(idp->val.id2));
		    else
			fprintf(stdout, "%s ", visbuf(idp->id));
		if (ctl->wildcard)
		    fputs("*", stdout);
	    }
	}

	if (ctl->fetchall || ctl->keep || ctl->flush || ctl->rewrite
			|| ctl->stripcr || ctl->forcecr || ctl->pass8bits)
	    fputs("options ", stdout);
	DUMPOPT(ctl->fetchall,    "fetchall");
	DUMPOPT(ctl->keep,        "keep");
	DUMPOPT(ctl->flush,       "flush");
	DUMPOPT(ctl->rewrite,     "rewrite");
	DUMPOPT(ctl->stripcr,     "stripcr"); 
	DUMPOPT(ctl->forcecr,     "forcecr");
	DUMPOPT(ctl->pass8bits,   "pass8bits");
	DUMPOPT(ctl->dropstatus,  "dropstatus");
	DUMPOPT(ctl->mimedecode,  "mimedecode");
#undef DUMPOPT

	if (ctl->mda)
	    fprintf(stdout, "mda \"%s\" ", visbuf(ctl->mda));
#ifdef INET6
	if (ctl->netsec)
	    fprintf(stdout, "netsec \"%s\" ", visbuf(ctl->netsec));
#endif /* INET6 */
	if (ctl->preconnect)
	    fprintf(stdout, "preconnect \"%s\" ", visbuf(ctl->preconnect));	
	if (ctl->postconnect)
	    fprintf(stdout, "postconnect \"%s\" ", visbuf(ctl->postconnect));	
	if (ctl->fetchlimit)
	    fprintf(stdout, "fetchlimit %d ", ctl->fetchlimit);
	if (ctl->batchlimit)
	    fprintf(stdout, "batchlimit %d ", ctl->batchlimit);

	if (ctl->smtphunt)
	{
	    struct idlist *idp;

	    fprintf(stdout, "smtphost ");
	    for (idp = ctl->smtphunt; idp; idp = idp->next)
		fprintf(stdout, "%s ", visbuf(idp->id));
	}

	if (ctl->smtpaddress)
	    fprintf(stdout, "smtpaddress \"%s\" ", visbuf(ctl->smtpaddress));

	if (ctl->antispam)
	    fprintf(stdout, "antispam %d ", ctl->antispam);

	if (ctl->mailboxes && ctl->mailboxes->id)
	{
	    struct idlist *idp;

	    fprintf(stdout, "mailboxes ");
	    for (idp = ctl->mailboxes; idp; idp = idp->next)
		fprintf(stdout, "%s ", visbuf(idp->id));
	}

	putc('\n', stdout);
    }
}

/* conf.c ends here */
