/* mx.h -- name-to-preference association for MX records */

struct mxentry
{
    unsigned char	*name;
    int			pref;
};

extern struct mxentry * getmxrecords(const unsigned char *);

/* some versions of FreeBSD should declare this but don't */
extern int h_errno;

/* mx.h ends here */
