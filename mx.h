/* mx.h -- name-to-preference association for MX records */

struct mxentry
{
    char	*name;
    int		pref;
};

#ifdef HAVE_PROTOTYPES
extern struct mxentry * getmxrecords(const char *);
#endif /* HAVE_PROTOTYPES */

/* mx.h ends here */
