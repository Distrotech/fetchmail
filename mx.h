/* mx.h -- name-to-preference association for MX records */

struct mxentry
{
    char	*name;
    int		pref;
};

extern struct mxentry * getmxrecords(const char *);

/* mx.h ends here */
