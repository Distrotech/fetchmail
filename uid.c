/*
 * uid.c -- UIDL handling for POP3 servers without LAST
 *
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"

#include <stdio.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#include <string.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include "fetchmail.h"

/*
 * Machinery for handling UID lists live here.  This is mainly to support
 * RFC1725-conformant POP3 servers without a LAST command, but may also be
 * useful for making the IMAP4 querying logic UID-oriented, if a future
 * revision of IMAP forces me to.
 *
 * Here's the theory:
 *
 * At start of a query, we have a (possibly empty) list of UIDs to be
 * considered seen in `oldsaved'.  These are messages that were left in
 * the mailbox and *not deleted* on previous queries (we don't need to
 * remember the UIDs of deleted messages because ... well, they're gone!)
 * This list is initially set up by initialized_saved_list() from the
 * .fetchids file.
 *
 * Early in the query, during the execution of the protocol-specific 
 * getrange code, the driver expects that the host's `newsaved' member
 * will be filled with a list of UIDs and message numbers representing
 * the mailbox state.  If this list is empty, the server did
 * not respond to the request for a UID listing.
 *
 * Each time a message is fetched, we can check its UID against the
 * `oldsaved' list to see if it is old.  If not, it should be downloaded
 * (and possibly deleted).  It should be downloaded anyway if --all
 * is on.  It should not be deleted if --keep is on.
 *
 * Each time a message is deleted, we remove its id from the `newsaved'
 * member.
 *
 * At the end of the query, whatever remains in the `newsaved' member
 * (because it was not deleted) becomes the `oldsaved' list.  The old
 * `oldsaved' list is freed.
 *
 * At the end of the fetchmail run, all current `oldsaved' lists are
 * flushed out to the .fetchids file to be picked up by the next run.
 * If there are no such messages, the file is deleted.
 *
 * Note: all comparisons are caseblind!
 */

/* UIDs associated with un-queried hosts */
static struct idlist *scratchlist;

void initialize_saved_lists(struct query *hostlist, const char *idfile)
/* read file of saved IDs and attach to each host */
{
    int	st;
    FILE	*tmpfp;
    struct query *ctl;

    /* make sure lists are initially empty */
    for (ctl = hostlist; ctl; ctl = ctl->next)
	ctl->oldsaved = ctl->newsaved = (struct idlist *)NULL;

    /* let's get stored message UIDs from previous queries */
    if ((tmpfp = fopen(idfile, "r")) != (FILE *)NULL) {
	char buf[POPBUFSIZE+1],host[HOSTLEN+1],user[USERNAMELEN+1],id[IDLEN+1];

	while (fgets(buf, POPBUFSIZE, tmpfp) != (char *)NULL)
	{
	    /* possible lossage here with very old versions of sscanf(3)... */
	    if ((st = sscanf(buf, "%[^@]@%s %s\n", user, host, id)) == 3)
	    {
		for (ctl = hostlist; ctl; ctl = ctl->next)
		{
		    if (strcasecmp(host, ctl->server.names->id) == 0
				&& strcasecmp(user, ctl->remotename) == 0)
		    {
			save_str(&ctl->oldsaved, -1, id);
			break;
		    }
		}

		/* if it's not in a host we're querying, save it anyway */
		if (ctl == (struct query *)NULL)
		    save_str(&scratchlist, -1, buf);
	    }
	}
	fclose(tmpfp);
    }
}

struct idlist *save_str(struct idlist **idl, int num, const char *str)
/* save a number/UID pair on the given UID list */
{
    struct idlist **end;

    /* do it nonrecursively so the list is in the right order */
    for (end = idl; *end; end = &(*end)->next)
	continue;

    *end = (struct idlist *)xmalloc(sizeof(struct idlist));
    (*end)->val.num = num;
    (*end)->id = str ? xstrdup(str) : (char *)NULL;
    (*end)->next = NULL;

    return(*end);
}

void free_str_list(struct idlist **idl)
/* free the given UID list */
{
    if (*idl == (struct idlist *)NULL)
	return;

    free_str_list(&(*idl)->next);
    free ((*idl)->id);
    free(*idl);
    *idl = (struct idlist *)NULL;
}

void save_str_pair(struct idlist **idl, const char *str1, const char *str2)
/* save an ID pair on the given list */
{
    struct idlist **end;

    /* do it nonrecursively so the list is in the right order */
    for (end = idl; *end; end = &(*end)->next)
	continue;

    *end = (struct idlist *)xmalloc(sizeof(struct idlist));
    (*end)->id = str1 ? xstrdup(str1) : (char *)NULL;
    if (str2)
	(*end)->val.id2 = xstrdup(str2);
    else
	(*end)->val.id2 = (char *)NULL;
    (*end)->next = (struct idlist *)NULL;
}

#ifdef __UNUSED__
void free_str_pair_list(struct idlist **idl)
/* free the given ID pair list */
{
    if (*idl == (struct idlist *)NULL)
	return;

    free_idpair_list(&(*idl)->next);
    free ((*idl)->id);
    free ((*idl)->val.id2);
    free(*idl);
    *idl = (struct idlist *)NULL;
}
#endif

int str_in_list(struct idlist **idl, const char *str)
/* is a given ID in the given list? (comparison is caseblind) */
{
    if (*idl == (struct idlist *)NULL || str == (char *) NULL)
	return(0);
    else if (strcasecmp(str, (*idl)->id) == 0)
	return(1);
    else
	return(str_in_list(&(*idl)->next, str));
}

char *str_find(struct idlist **idl, int number)
/* return the id of the given number in the given list. */
{
    if (*idl == (struct idlist *) 0)
	return((char *) 0);
    else if (number == (*idl)->val.num)
	return((*idl)->id);
    else
	return(str_find(&(*idl)->next, number));
}

char *idpair_find(struct idlist **idl, const char *id)
/* return the id of the given id in the given list (caseblind comparison) */
{
    if (*idl == (struct idlist *) 0)
	return((char *) 0);
    else if (strcasecmp(id, (*idl)->id) == 0)
	return((*idl)->val.id2 ? (*idl)->val.id2 : (*idl)->id);
    else
	return(idpair_find(&(*idl)->next, id));
}

int delete_str(struct idlist **idl, int num)
/* delete given message from given list */
{
    if (*idl == (struct idlist *)NULL)
	return(0);
    else if ((*idl)->val.num == num)
    {
	struct idlist	*next = (*idl)->next;

	free ((*idl)->id);
	free(*idl);
	*idl = next;
	return(1);
    }
    else
	return(delete_str(&(*idl)->next, num));
    return(0);
}

void append_str_list(struct idlist **idl, struct idlist **nidl)
/* append nidl to idl (does not copy *) */
{
    if ((*idl) == (struct idlist *)NULL)
	*idl = *nidl;
    else if ((*idl)->next == (struct idlist *)NULL)
	(*idl)->next = *nidl;
    else if ((*idl)->next != *nidl)
	append_str_list(&(*idl)->next, nidl);
}

void update_str_lists(struct query *ctl)
/* perform end-of-query actions on UID lists */
{
    free_str_list(&ctl->oldsaved);
    ctl->oldsaved = ctl->newsaved;
    ctl->newsaved = (struct idlist *) NULL;
}

void write_saved_lists(struct query *hostlist, const char *idfile)
/* perform end-of-run write of seen-messages list */
{
    int		idcount;
    FILE	*tmpfp;
    struct query *ctl;
    struct idlist *idp;

    /* if all lists are empty, nuke the file */
    idcount = 0;
    for (ctl = hostlist; ctl; ctl = ctl->next) {
	if (ctl->oldsaved)
	    idcount++;
    }

    /* either nuke the file or write updated last-seen IDs */
    if (!idcount)
	unlink(idfile);
    else
	if ((tmpfp = fopen(idfile, "w")) != (FILE *)NULL) {
	    for (ctl = hostlist; ctl; ctl = ctl->next) {
		for (idp = ctl->oldsaved; idp; idp = idp->next)
		    fprintf(tmpfp, "%s@%s %s\n", 
			    ctl->remotename, ctl->server.names->id, idp->id);
	    }
	    for (idp = scratchlist; idp; idp = idp->next)
		fputs(idp->id, tmpfp);
	    fclose(tmpfp);
	}
}

/* uid.c ends here */
