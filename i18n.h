/* Dummy header for libintl.h */

#undef _
#ifdef ENABLE_NLS
#undef __OPTIMIZE__
#include <libintl.h>
#define GT_(String) gettext((String))
#define NGT_(String) (String)
#else
#define GT_(String) (String)
#define NGT_(String) (String)
#endif
