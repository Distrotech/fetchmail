/* acconfig.h
   This file is in the public domain.

   Descriptive text for the C preprocessor macros that
   the distributed Autoconf macros can define.
   No software package will use all of them; autoheader copies the ones
   your configure.in uses into your configuration header file templates.

   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  Although this order
   can split up related entries, it makes it easier to check whether
   a given entry is in the file.

   Leave the following blank line there!!  Autoheader needs it.  */


/* Define if you have res_search available in your bind library */
#undef HAVE_RES_SEARCH

/* Define if you have herror available in your bind library */
#undef HAVE_HERROR

/* Define if your C compiler allows void * as a function result */
#undef HAVE_VOIDPOINTER

/* Define if `union wait' is the type of the first arg to wait functions.  */
#undef HAVE_UNION_WAIT

/* Define if you have the strcasecmp function.  */
#undef HAVE_STRCASECMP

/* Define if you have GNU's getopt family of functions.  */
#undef HAVE_GETOPTLONG


/* Leave that blank line there!!  Autoheader needs it.
   If you're adding to this file, keep in mind:
   The entries are in sort -df order: alphabetical, case insensitive,
   ignoring punctuation (such as underscores).  */
