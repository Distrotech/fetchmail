/* netrc.c -- parse the .netrc file to get hosts, accounts, and passwords
   Copyright (C) 1996, Free Software Foundation, Inc.
   Gordon Matzigkeit <gord@gnu.ai.mit.edu>, 1996

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* Compile with -DSTANDALONE to test this module. */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

/* If SYSTEM_WGETRC is defined in config.h, then we assume we are being
   compiled as a part of Wget.  That means we make special Wget-specific
   modifications to the code (at least until we settle on a cleaner
   library interface). */
/* FIXME - eliminate all WGET_HACKS conditionals by massaging Wget. */
#ifdef SYSTEM_WGETRC
# define WGET_HACKS 1
#endif

/* If CLIENT_TIMEOUT is defined in config.h, then we assume we are being
   compiled as a part of fetchmail. */
/* FIXME - eliminate all FETCHMAIL_HACKS conditionals by fixing fetchmail. */
#ifdef CLIENT_TIMEOUT
# define FETCHMAIL_HACKS 1
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
#  include <string.h>
#else
#  include <strings.h>
#endif

#if ENABLE_NLS
# include <libintl.h>
# define _(Text) gettext (Text)
#else
# define textdomain(Domain)
# define _(Text) Text
#endif

#include "netrc.h"

#ifdef STANDALONE
/* Normally defined in xstrdup.c. */
# define xstrdup strdup

/* Normally defined in xmalloc.c */
# define xmalloc malloc
# define xrealloc realloc
#endif

#if defined(STANDALONE) || defined(WGET_HACKS) || defined(FETCHMAIL_HACKS)
/* We need to implement our own dynamic strings. */
typedef struct
{
  int ds_length;
  char *ds_string;
} dynamic_string;
#else
/* We must be part of libit, or another GNU program, so assume that we have
   the ERROR function */
# define HAVE_ERROR 1
# include "error.h"
# include "dstring.h"
#endif

#define DS_INIT_LENGTH 40

#ifdef WGET_HACKS
/* Wget uses different naming conventions. */
# define xmalloc nmalloc
# define xstrdup nstrdup
# define xrealloc nrealloc

/* Wget has read_whole_line defined in utils.c */
# include "utils.h"

/* Temporary dynamic string (dstring.c from libit)-like interface to
   using read_whole_line. */
#define ds_init(string, size) ((string)->ds_string = NULL)
#define ds_destroy(string) free ((string)->ds_string)

/* We use read_whole_line to implement ds_fgets. */
static char *
ds_fgets (FILE *f, dynamic_string *s)
{
  free (s->ds_string);
  s->ds_string = read_whole_line (f);
  return s->ds_string;
}
#endif /* WGET_HACKS */

#ifdef FETCHMAIL_HACKS
/* fetchmail, too, is not consistent with the xmalloc functions. */
# define xrealloc realloc
# define xstrdup strdup
#endif

#if defined(STANDALONE) || defined(FETCHMAIL_HACKS)
/* Bits and pieces of Tom Tromey's dstring.c, taken from libit-0.2. */

/* Initialize dynamic string STRING with space for SIZE characters.  */

void
ds_init (string, size)
     dynamic_string *string;
     int size;
{
  string->ds_length = size;
  string->ds_string = (char *) xmalloc (size);
}

/* Expand dynamic string STRING, if necessary, to hold SIZE characters.  */

void
ds_resize (string, size)
     dynamic_string *string;
     int size;
{
  if (size > string->ds_length)
    {
      string->ds_length = size;
      string->ds_string = (char *) xrealloc ((char *) string->ds_string, size);
    }
}

/* Delete dynamic string.  */

void
ds_destroy (string)
     dynamic_string *string;
{
  free (string->ds_string);
  string->ds_string = NULL;
}

/* Dynamic string S gets a string terminated by the EOS character
   (which is removed) from file F.  S will increase
   in size during the function if the string from F is longer than
   the current size of S.
   Return NULL if end of file is detected.  Otherwise,
   Return a pointer to the null-terminated string in S.  */

char *
ds_fgetstr (f, s, eos)
     FILE *f;
     dynamic_string *s;
     char eos;
{
  int insize;			/* Amount needed for line.  */
  int strsize;			/* Amount allocated for S.  */
  int next_ch;

  /* Initialize.  */
  insize = 0;
  strsize = s->ds_length;

  /* Read the input string.  */
  next_ch = getc (f);
  while (next_ch != eos && next_ch != EOF)
    {
      if (insize >= strsize - 1)
	{
	  ds_resize (s, strsize * 2 + 2);
	  strsize = s->ds_length;
	}
      s->ds_string[insize++] = next_ch;
      next_ch = getc (f);
    }
  s->ds_string[insize++] = '\0';

  if (insize == 1 && next_ch == EOF)
    return NULL;
  else
    return s->ds_string;
}

char *
ds_fgets (f, s)
     FILE *f;
     dynamic_string *s;
{
  return ds_fgetstr (f, s, '\n');
}
#endif /* !STANDALONE */


/* Maybe add NEWENTRY to the account information list, LIST.  NEWENTRY is
   set to a ready-to-use netrc_entry, in any event. */
static void
maybe_add_to_list (newentry, list)
     netrc_entry **newentry;
     netrc_entry **list;
{
  netrc_entry *a, *l;
  a = *newentry;
  l = *list;

  /* We need an account name in order to add the entry to the list. */
  if (a && ! a->account)
    {
      /* Free any allocated space. */
      free (a->host);
      free (a->account);
      free (a->password);
    }
  else
    {
      if (a)
	{
	  /* Add the current machine into our list. */
	  a->next = l;
	  l = a;
	}

      /* Allocate a new netrc_entry structure. */
      a = (netrc_entry *) xmalloc (sizeof (netrc_entry));
    }

  /* Zero the structure, so that it is ready to use. */
  memset (a, 0, sizeof(*a));

  /* Return the new pointers. */
  *newentry = a;
  *list = l;
  return;
}


/* Parse FILE as a .netrc file (as described in ftp(1)), and return a
   list of entries.  NULL is returned if the file could not be
   parsed. */
netrc_entry *
parse_netrc (file)
     char *file;
{
  FILE *fp;
  char *p, *tok, *premature_token;
  netrc_entry *current, *retval;
  dynamic_string line;
  int ln;

  /* The latest token we've seen in the file. */
  enum
  {
    tok_nothing, tok_account, tok_login, tok_macdef, tok_machine, tok_password
  } last_token = tok_nothing;

  current = retval = NULL;

  fp = fopen (file, "r");
  if (!fp)
    {
      /* Just return NULL if we can't open the file. */
      return NULL;
    }

  /* Initialize the file data. */
  ln = 0;
  premature_token = NULL;

  /* While there are lines in the file... */
  ds_init (&line, DS_INIT_LENGTH);
  while (ds_fgets (fp, &line))
    {
      ln ++;

      /* Parse the line. */
      p = line.ds_string;

      /* If the line is empty, then end any macro definition. */
      if (last_token == tok_macdef && !*p)
	/* End of macro if the line is empty. */
	last_token = tok_nothing;

      /* If we are defining macros, then skip parsing the line. */
      while (*p && last_token != tok_macdef)
	{
	  /* Skip any whitespace. */
	  while (*p && isspace (*p))
	    p ++;

	  /* Discard end-of-line comments. */
	  if (*p == '#')
	    break;

	  tok = p;

	  /* Find the end of the token. */
	  while (*p && !isspace (*p))
	    p ++;

	  /* Null-terminate the token, if it isn't already. */
	  if (*p)
	    *p ++ = '\0';

	  switch (last_token)
	    {
	    case tok_login:
	      if (current)
		current->account = (char *) xstrdup (tok);
	      else
		premature_token = "login";
	      break;

	    case tok_machine:
	      /* Start a new machine entry. */
	      maybe_add_to_list (&current, &retval);
	      current->host = (char *) xstrdup (tok);
	      break;

	    case tok_password:
	      if (current)
		current->password = (char *) xstrdup (tok);
	      else
		premature_token = "password";
	      break;

	      /* We handle most of tok_macdef above. */
	    case tok_macdef:
	      if (!current)
		premature_token = "macdef";
	      break;

	      /* We don't handle the account keyword at all. */
	    case tok_account:
	      if (!current)
		premature_token = "account";
	      break;

	      /* We handle tok_nothing below this switch. */
	    case tok_nothing:
	      break;
	    }

	  if (premature_token)
	    {
#ifdef HAVE_ERROR
	      error_at_line (0, 0, file, ln,
			     _("warning: found \"%s\" before any host names"),
			     premature_token);
#else
	      fprintf (stderr,
		       "%s:%d: warning: found \"%s\" before any host names\n",
		       file, ln, premature_token);
#endif
	      premature_token = NULL;
	    }

	  if (last_token != tok_nothing)
	    /* We got a value, so reset the token state. */
	    last_token = tok_nothing;
	  else
	    {
	      /* Fetch the next token. */
	      if (!strcmp (tok, "account"))
		last_token = tok_account;

	      if (!strcmp (tok, "default"))
		{
		  maybe_add_to_list (&current, &retval);
		}
	      else if (!strcmp (tok, "login"))
		last_token = tok_login;

	      else if (!strcmp (tok, "macdef"))
		last_token = tok_macdef;

	      else if (!strcmp (tok, "machine"))
		last_token = tok_machine;

	      else if (!strcmp (tok, "password"))
		last_token = tok_password;

	      else
		{
		  fprintf (stderr, _("%s:%d: warning: unknown token \"%s\"\n"),
			   file, ln, tok);
		}
	    }
	}
    }

  ds_destroy (&line);
  fclose (fp);

  /* Finalize the last machine entry we found. */
  maybe_add_to_list (&current, &retval);
  free (current);

  /* Reverse the order of the list so that it appears in file order. */
  current = retval;
  retval = NULL;
  while (current)
    {
      netrc_entry *saved_reference;

      /* Change the direction of the pointers. */
      saved_reference = current->next;
      current->next = retval;

      /* Advance to the next node. */
      retval = current;
      current = saved_reference;
    }

  return retval;
}


/* Return the netrc entry from LIST corresponding to HOST.  NULL is
   returned if no such entry exists. */
netrc_entry *
search_netrc (list, host)
     netrc_entry *list;
     char *host;
{
  /* Look for the HOST in LIST. */
  while (list)
    {
      if (!list->host)
	/* We hit the default entry. */
	break;

      else if (!strcmp (list->host, host))
	/* We found a matching entry. */
	break;

      list = list->next;
    }

  /* Return the matching entry, or NULL. */
  return list;
}


#ifdef STANDALONE
#include <sys/types.h>
#include <sys/stat.h>

extern int errno;

int
main (argc, argv)
     int argc;
     char **argv;
{
  struct stat sb;
  char *program_name, *file, *target;
  netrc_entry *head, *a;

  if (argc < 2)
    {
      fprintf (stderr, "Usage: %s NETRC [HOSTNAME]...\n", argv[0]);
      exit (1);
    }

  program_name = argv[0];
  file = argv[1];
  target = argv[2];

  if (stat (file, &sb))
    {
      fprintf (stderr, "%s: cannot stat %s: %s\n", argv[0], file,
	       strerror (errno));
      exit (1);
    }

  head = parse_netrc (file);
  if (!head)
    {
      fprintf (stderr, "%s: no entries found in %s\n", argv[0], file);
      exit (1);
    }

  if (argc > 2)
    {
      int i, status;
      status = 0;
      for (i = 2; i < argc; i++)
	{
	  /* Print out the host that we are checking for. */
	  fputs (argv[i], stdout);

	  a = search_netrc (head, argv[i]);
	  if (a)
	    {
	      /* Print out the account and password (if any). */
	      fputc (' ', stdout);
	      fputs (a->account, stdout);
	      if (a->password)
		{
		  fputc (' ', stdout);
		  fputs (a->password, stdout);
		}
	    }
	  else
	    status = 1;

	  fputc ('\n', stdout);
	}
      exit (status);
    }

  /* Print out the entire contents of the netrc. */
  a = head;
  while (a)
    {
      /* Print the host name. */
      if (a->host)
	fputs (a->host, stdout);
      else
	fputs ("DEFAULT", stdout);

      fputc (' ', stdout);

      /* Print the account name. */
      fputs (a->account, stdout);

      if (a->password)
	{
	  /* Print the password, if there is any. */
	  fputc (' ', stdout);
	  fputs (a->password, stdout);
	}

      fputc ('\n', stdout);
      a = a->next;
    }

  exit (0);
}
#endif /* STANDALONE */
