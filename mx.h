/* mx.h -- name-to-preference association for MX records.
 * For license terms, see the file COPYING in this directory.
 */

#include "config.h"

#include <netdb.h>

struct mxentry
{
    char	*name;
    int		pref;
};

extern struct mxentry * getmxrecords(const char *);

#if !HAVE_DECL_H_ERRNO
extern int h_errno;
#endif

/* mx.h ends here */
