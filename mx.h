/* mx.h -- name-to-preference association for MX records */

struct mxentry
{
    char	*name;
    int		pref;
};

#ifdef HAVE_PROTOTYPES
extern int getmxrecords(char *, int, struct mxentry *);
#endif /* HAVE_PROTOTYPES */

/* mx.h ends here */
