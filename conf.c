/*
 * conf.c -- dump fetchmail configuration as Python dictionary initializer
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"
#include "tunable.h"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>

#include "fetchmail.h"

/* Python prettyprinting functions */

static int indent_level;

static void indent(char ic)
/* indent current line */
{
    int	i;

    if (ic == ')' || ic == ']' || ic == '}')
	indent_level--;

    /*
     * The guard here is a kluge.  It depends on the fact that in the
     * particular structure we're dumping, opening [s are always
     * initializers for dictionary members and thus will be preceded
     * by a member name.
     */
    if (ic != '[')
    {
	for (i = 0; i < indent_level / 2; i++)
	    putc('\t', stdout);
	if (indent_level % 2)
	    fputs("    ", stdout);
    }

    if (ic)
    {
	putc(ic, stdout);
	putc('\n', stdout);
    }

    if (ic == '(' || ic == '[' || ic == '{')
	indent_level++;
}


static void stringdump(const char *name, const char *member)
/* dump a string member with current indent */
{
    indent('\0');
    fprintf(stdout, "\"%s\":", name);
    if (member)
	fprintf(stdout, "\"%s\"", visbuf(member));
    else
	fputs("None", stdout);
    fputs(",\n", stdout);
}

static void numdump(const char *name, const int num)
/* dump a numeric quantity at current indent */
{
    indent('\0');
    fprintf(stdout, "'%s':%d,\n", name, NUM_VALUE_OUT(num));
}

static void booldump(const char *name, const int onoff)
/* dump a boolean quantity at current indent */
{
    indent('\0');
    if (onoff)
	fprintf(stdout, "'%s':TRUE,\n", name);
    else
	fprintf(stdout, "'%s':FALSE,\n", name);
}

static void listdump(const char *name, struct idlist *list)
/* dump a string list member with current indent */
{
    indent('\0');
    fprintf(stdout, "\"%s\":", name);

    if (!list)
	fputs("[],\n", stdout);
    else
    {
	struct idlist *idp;

	fputs("[", stdout);
	for (idp = list; idp; idp = idp->next)
	    if (idp->id)
	    {
		fprintf(stdout, "\"%s\"", visbuf(idp->id));
		if (idp->next)
		    fputs(", ", stdout);
	    }
	fputs("],\n", stdout);
    }
}

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
    const char *features;
#ifdef MAPI_ENABLE
    const char *languages;
#endif /* MAPI_ENABLE */


    indent_level = 0;

    /*
     * These had better match the values fetchmailconf is expecting!
     * (We don't want to import them from Tkinter because the user
     * might not have it installed.)
     */
    fputs("TRUE=1; FALSE=0\n\n", stdout);

    /*
     * We need this in order to know whether `interface' and `monitor'
     * are valid options or not.
     */
#if defined(linux)
    fputs("os_type = 'linux'\n", stdout);
#elif defined(__FreeBSD__)
    fputs("os_type = 'freebsd'\n", stdout);
#else
    fputs("os_type = 'generic'\n", stdout);
#endif

    /* 
     * This should be approximately in sync with the -V option dumping 
     * in fetchmail.c.
     */
    features = "feature_options = ("
#ifdef POP3_ENABLE
    "'pop3',"
#endif /* POP3_ENABLE */
#ifdef IMAP_ENABLE
    "'imap',"
#endif /* IMAP_ENABLE */
#ifdef GSSAPI
    "'gssapi',"
#endif /* GSSAPI */
#ifdef RPA_ENABLE
    "'rpa',"
#endif /* RPA_ENABLE */
#ifdef SDPS_ENABLE
    "'sdps',"
#endif /* SDPS_ENABLE */
#ifdef ETRN_ENABLE
    "'etrn',"
#endif /* ETRN_ENABLE */
#ifdef ODMR_ENABLE
    "'odmr',"
#endif /* ODMR_ENABLE */
#ifdef SSL_ENABLE
    "'ssl',"
#endif /* SSL_ENABLE */
#ifdef OPIE_ENABLE
    "'opie',"
#endif /* OPIE_ENABLE */
#ifdef HAVE_SOCKS
    "'socks',"
#endif /* HAVE_SOCKS */
#ifdef MAPI_ENABLE
    "'mapi',"
#endif /* MAPI_ENABLE */
    ")\n";
    fputs(features, stdout);

    fputs("# Start of configuration initializer\n", stdout);
    fputs("fetchmailrc = ", stdout);
    indent('{');

    numdump("poll_interval", runp->poll_interval);
    stringdump("logfile", runp->logfile);
    stringdump("idfile", runp->idfile);
    stringdump("postmaster", runp->postmaster);
    booldump("bouncemail", runp->bouncemail);
    booldump("spambounce", runp->spambounce);
    booldump("softbounce", runp->softbounce);
    stringdump("properties", runp->properties);
    booldump("invisible", runp->invisible);
    booldump("showdots", runp->showdots);
    booldump("syslog", runp->use_syslog);

    if (!querylist)
    {
	fputs("    'servers': []\n", stdout);
	goto alldone;
    }

    indent(0);
    fputs("# List of server entries begins here\n", stdout);
    indent(0);
    fputs("'servers': ", stdout);
    indent('[');

    for (ctl = querylist; ctl; ctl = ctl->next)
    {
	/*
	 * First, the server stuff.
	 */
	if (!ctl->server.lead_server)
	{
	    flag	using_kpop;

	    /*
	     * Every time we see a leading server entry after the first one,
	     * it implicitly ends the both (a) the list of user structures
	     * associated with the previous entry, and (b) that previous entry.
	     */
	    if (ctl > querylist)
	    {
		indent(']');
		indent('}');
		indent('\0'); 
		putc(',', stdout);
		putc('\n', stdout);
	    }

	    indent(0);
	    fprintf(stdout,"# Entry for site `%s' begins:\n",ctl->server.pollname);
	    indent('{');

	    using_kpop =
		(ctl->server.protocol == P_POP3 &&
		 ctl->server.service && !strcmp(ctl->server.service, KPOP_PORT ) &&
		 ctl->server.authenticate == A_KERBEROS_V5);

	    stringdump("pollname", ctl->server.pollname); 
	    booldump("active", !ctl->server.skip); 
	    stringdump("via", ctl->server.via); 
	    stringdump("protocol", 
		       using_kpop ? "KPOP" : showproto(ctl->server.protocol));
	    stringdump("service",  ctl->server.service);
	    numdump("timeout",  ctl->server.timeout);
	    numdump("interval", ctl->server.interval);

	    if (ctl->server.envelope == STRING_DISABLED)
		stringdump("envelope", NULL); 
	    else if (ctl->server.envelope == NULL)
		stringdump("envelope", "Received"); 		
	    else
		stringdump("envelope", ctl->server.envelope); 
	    numdump("envskip", ctl->server.envskip);
	    stringdump("qvirtual", ctl->server.qvirtual);
 
	    switch (ctl->server.authenticate) {
		case A_ANY:
		    stringdump("auth", "any"); break;
		case A_PASSWORD:
		    stringdump("auth", "password"); break;
		case A_OTP:
		    stringdump("auth", "otp"); break;
		case A_NTLM:
		    stringdump("auth", "ntlm"); break;
		case A_CRAM_MD5:
		    stringdump("auth", "cram-md5"); break;
		case A_GSSAPI:
		    stringdump("auth", "gssapi"); break;
		case A_KERBEROS_V5:
		    stringdump("auth", "kerberos_v5"); break;
		case A_SSH:
		    stringdump("auth", "ssh"); break;
		case A_MSN:
		    stringdump("auth", "msn"); break;
		default: abort();
	    }

#ifdef HAVE_RES_SEARCH
	    booldump("dns", ctl->server.dns);
#endif /* HAVE_RES_SEARCH */
	    listdump("aka", ctl->server.akalist);
	    listdump("localdomains", ctl->server.localdomains);

#ifdef CAN_MONITOR
	    stringdump("interface", ctl->server.interface);
	    stringdump("monitor", ctl->server.monitor);
#endif

	    stringdump("plugin", ctl->server.plugin);
	    stringdump("plugout", ctl->server.plugout);
	    stringdump("principal", ctl->server.principal);
	    if (ctl->server.esmtp_name)
	        stringdump("esmtpname",ctl->server.esmtp_name);
	    if (ctl->server.esmtp_password)
	        stringdump("esmtppassword",ctl->server.esmtp_password);
	    booldump("tracepolls", ctl->server.tracepolls);
	    indent(0);
	    switch(ctl->server.badheader) {
		/* this is a hack - we map this to a boolean option for
		 * fetchmailconf purposes */
		case BHREJECT: puts("'badheader': FALSE,"); break;
		case BHACCEPT: puts("'badheader': TRUE,"); break;
	    }

	    switch (ctl->server.retrieveerror) {
		case RE_ABORT: stringdump("retrieveerror", "abort"); break;
		case RE_CONTINUE: stringdump("retrieveerror", "continue"); break;
		case RE_MARKSEEN: stringdump("retrieveerror", "markseen"); break;
	    }

	    indent(0);
	    fputs("'users': ", stdout);
	    indent('[');
	}

	indent('{');

	stringdump("remote", ctl->remotename);
	stringdump("password", ctl->password);

	indent('\0');
	fprintf(stdout, "'localnames':[");
	for (idp = ctl->localnames; idp; idp = idp->next)
	{
	    char namebuf[USERNAMELEN + 1];

	    strlcpy(namebuf, visbuf(idp->id), sizeof(namebuf));
	    if (idp->val.id2)
		fprintf(stdout, "(\"%s\", %s)", namebuf, visbuf(idp->val.id2));
	    else
		fprintf(stdout, "\"%s\"", namebuf);
	    if (idp->next)
		fputs(", ", stdout);
	}
	if (ctl->wildcard)
	    fputs(", '*'", stdout);
	fputs("],\n", stdout);

	booldump("fetchall", ctl->fetchall);
	booldump("keep", ctl->keep);
	booldump("flush", ctl->flush);
	booldump("limitflush", ctl->limitflush);
	booldump("rewrite", ctl->rewrite);
	booldump("stripcr", ctl->stripcr); 
	booldump("forcecr", ctl->forcecr);
	booldump("pass8bits", ctl->pass8bits);
	booldump("dropstatus", ctl->dropstatus);
	booldump("dropdelivered", ctl->dropdelivered);
	booldump("mimedecode", ctl->mimedecode);
	booldump("idle", ctl->idle);

	stringdump("mda", ctl->mda);
	stringdump("bsmtp", ctl->bsmtp);
	indent('\0');
	if (ctl->listener == LMTP_MODE)
	    fputs("'lmtp':TRUE,\n", stdout);
	else
	    fputs("'lmtp':FALSE,\n", stdout);
	    
	stringdump("preconnect", ctl->preconnect);
	stringdump("postconnect", ctl->postconnect);
	numdump("limit", ctl->limit);
	numdump("warnings", ctl->warnings);
	numdump("fetchlimit", ctl->fetchlimit);
	numdump("fetchsizelimit", ctl->fetchsizelimit);
	numdump("fastuidl", ctl->fastuidl);
	numdump("batchlimit", ctl->batchlimit);
#ifdef SSL_ENABLE
	booldump("ssl", ctl->use_ssl);
	stringdump("sslkey", ctl->sslkey);
	stringdump("sslcert", ctl->sslcert);
	stringdump("sslproto", ctl->sslproto);
	booldump("sslcertck", ctl->sslcertck);
	stringdump("sslcertpath", ctl->sslcertpath);
	stringdump("sslcommonname", ctl->sslcommonname);
	stringdump("sslfingerprint", ctl->sslfingerprint);
#endif /* SSL_ENABLE */
	numdump("expunge", ctl->expunge);
	stringdump("properties", ctl->properties);
#ifdef MAPI_ENABLE
	numdump("mapi_exchange_version", ctl->mapi_exchange_version);
	stringdump("mapi_domain", ctl->mapi_domain);
	stringdump("mapi_realm", ctl->mapi_realm);
	stringdump("mapi_language", ctl->mapi_language);
#endif
	listdump("smtphunt", ctl->smtphunt);
	listdump("fetchdomains", ctl->domainlist);
	stringdump("smtpaddress", ctl->smtpaddress);
	stringdump("smtpname", ctl->smtpname);

	indent('\0');
	fprintf(stdout, "'antispam':'");
	for (idp = ctl->antispam; idp; idp = idp->next)
	{
	    fprintf(stdout, "%d", idp->val.status.num);
	    if (idp->next)
		fputs(" ", stdout);
	}
	fputs("',\n", stdout);
	listdump("mailboxes", ctl->mailboxes);

	indent('}');
	indent('\0'); 
	fputc(',', stdout);
    }

    /* end last span of user entries and last server entry */
    indent(']');
    indent('}');

    /* end array of servers */
    indent(']');

 alldone:
    /* end top-level dictionary */
    indent('}');

#ifdef MAPI_ENABLE
    languages = "languages=['Afrikaans',\n 'Albanian',\n 'Amharic (Ethiopia)',\n 'Arabic (Algeria)',\n 'Arabic (Bahrain)',\n 'Arabic (Egypt)',\n 'Arabic (Iraq)',\n 'Arabic (Jordan)',\n 'Arabic (Kuwait)',\n 'Arabic (Lebanon)',\n 'Arabic (Libya)',\n 'Arabic (Morocco)',\n 'Arabic (Oman)',\n 'Arabic (Qatar)',\n 'Arabic (Saudi Arabia)',\n 'Arabic (Syria)',\n 'Arabic (Tunisia)',\n 'Arabic (U.A.E.)',\n 'Arabic (Yemen)',\n 'Armenian',\n 'Assamese',\n 'Azeri (Cyrillic)',\n 'Azeri (Latin)',\n 'Basque',\n 'Belarusian',\n 'Bengali (India)',\n 'Bosnian (Bosnia/Herzegovina)',\n 'Breton (France)',\n 'Bulgarian',\n 'Catalan',\n 'Chinese (Hong Kong S.A.R.)',\n 'Chinese (Macau S.A.R.)',\n 'Chinese (PRC)',\n 'Chinese (Singapore)',\n 'Chinese (Taiwan)',\n 'Croatian',\n 'Croatian (Bosnia/Herzegovina)',\n 'Czech',\n 'Danish',\n 'Dari (Afghanistan)',\n 'Divehi',\n 'Dutch (Belgium)',\n 'Dutch (Netherlands)',\n 'English (Australia)',\n 'English (Belize)',\n 'English (Canada)',\n 'English (Caribbean)',\n 'English (India)',\n 'English (Ireland)',\n 'English (Jamaica)',\n 'English (New Zealand)',\n 'English (Philippines)',\n 'English (South Africa)',\n 'English (Trinidad)',\n 'English (United Kingdom)',\n 'English (United States)',\n 'English (Zimbabwe)',\n 'Estonian',\n 'Faroese',\n 'Farsi',\n 'Filipino',\n 'Finnish',\n 'French (Belgium)',\n 'French (Cameroon)',\n 'French (Canada)',\n 'French (Congo,DRC)',\n 'French (Cote d\\'Ivoire)',\n 'French (France)',\n 'French (Luxembourg)',\n 'French (Mali)',\n 'French (Monaco)',\n 'French (Morocco)',\n 'French (Senegal)',\n 'French (Switzerland)',\n 'French (West Indies)',\n 'Frisian (Netherlands)',\n 'FYRO Macedonian',\n 'Gaelic Ireland',\n 'Galician (Spain)',\n 'Georgian',\n 'German (Austria)',\n 'German (Germany)',\n 'German (Liechtenstein)',\n 'German (Luxembourg)',\n 'German (Switzerland)',\n 'Greek',\n 'Gujarati',\n 'Hebrew',\n 'Hindi',\n 'Hungarian',\n 'Icelandic',\n 'Igbo (Nigeria)',\n 'Indonesian',\n 'Italian (Italy)',\n 'Italian (Switzerland)',\n 'Japanese',\n 'Kannada',\n 'Kazakh',\n 'Khmer',\n 'Konkani',\n 'Korean',\n 'Kyrgyz (Cyrillic)',\n 'Lao',\n 'Latvian',\n 'Lithuanian',\n 'Macedonian',\n 'Malay (Brunei Darussalam)',\n 'Malay (Malaysia)',\n 'Malayalam',\n 'Maltese',\n 'Maori (New Zealand)',\n 'Marathi',\n 'Mongolian (Cyrillic)',\n 'Mongolian (Mongolia)',\n 'Nepali',\n 'Norwegian (Bokmal)',\n 'Norwegian (Nynorsk)',\n 'Oriya',\n 'Polish',\n 'Portuguese (Brazil)',\n 'Portuguese (Portugal)',\n 'Punjabi',\n 'Rhaeto-Romanic',\n 'Romanian',\n 'Romanian (Moldova)',\n 'Russian',\n 'Sami Lappish',\n 'Sanskrit',\n 'Serbian (Cyrillic)',\n 'Serbian (Latin)',\n 'Sindhi',\n 'Sinhalese (Sri Lanka)',\n 'Slovak',\n 'Slovenian',\n 'Spanish (Argentina)',\n 'Spanish (Bolivia)',\n 'Spanish (Chile)',\n 'Spanish (Colombia)',\n 'Spanish (Costa Rica)',\n 'Spanish (Dominican Republic)',\n 'Spanish (Ecuador)',\n 'Spanish (El Salvador)',\n 'Spanish (Guatemala)',\n 'Spanish (Honduras)',\n 'Spanish (International Sort)',\n 'Spanish (Mexico)',\n 'Spanish (Nicaragua)',\n 'Spanish (Panama)',\n 'Spanish (Paraguay)',\n 'Spanish (Peru)',\n 'Spanish (Puerto Rico)',\n 'Spanish (Traditional Sort)',\n 'Spanish (Uruguay)',\n 'Spanish (Venezuela)',\n 'Swahili',\n 'Swedish',\n 'Swedish (Finland)',\n 'Tajik',\n 'Tamil',\n 'Tatar',\n 'Telegu',\n 'Thai',\n 'Tibetan',\n 'Tsonga',\n 'Twana',\n 'Turkish',\n 'Turkmen',\n 'Ukrainian',\n 'Urdu',\n 'Uzbek (Cyrillic)',\n 'Uzbek (Latin)',\n 'Venda',\n 'Vietnamese',\n 'Welsh',\n 'Wolof (Senegal)',\n 'Xhosa',\n 'Zulu']\n";
    fputs(languages, stdout);
#endif /* MAPI_ENABLE */
  
    fputs("# End of initializer\n", stdout);
}

/* conf.c ends here */
