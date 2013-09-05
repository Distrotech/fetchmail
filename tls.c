/** \file tls.c - collect common TLS functionality 
 * \author Matthias Andree
 * \date 2006
 */

#include "fetchmail.h"

#include <stdbool.h>
#include <strings.h>

#include "gettext.h"

// FIXME: this needs to be a struct of name and enum value
static const char *const tlsm_names[] = {
 [TLSM_NONE] = "none",
 [TLSM_WRAPPED] = "wrapped",
 [TLSM_STLS_MAY] = "starttls=may",
 [TLSM_STLS_MUST] = "starttls=must"
};
const int TLSM_NAMESCOUNT = sizeof(tlsm_names) / sizeof(tlsm_names[0]);

/** return true if user allowed STARTTLS */
bool maybe_starttls(const struct query *ctl) {
         /* opportunistic or forced STARTTLS */
#ifdef SSL_ENABLE
    return ctl->sslmode != TLSM_NONE && ctl->sslmode != TLSM_WRAPPED;
#else
    (void)ctl;
    return false;
#endif
}

/** return true if user requires STARTTLS, note though that this code must
 * always use a logical AND with maybe_starttls(). */
bool must_starttls(const struct query *ctl) {
#ifdef SSL_ENABLE
    return maybe_starttls(ctl)
	&& (ctl->sslfingerprint || ctl->sslcertck
		|| ctl->sslmode == TLSM_STLS_MUST);
#else
    (void)ctl;
    return false;
#endif
}

/** return true if use requires TLS-wrapped mode (dedicated port) */
bool must_wrap_tls(const struct query *ctl) {
#ifdef SSL_ENABLE
    return ctl->sslmode == TLSM_WRAPPED;
#else
    (void)ctl;
    return false;
#endif
}

const char *tlsm_string(const e_sslmode tlsm) {
    if (tlsm >= 0 && tlsm < TLSM_NAMESCOUNT)
	return tlsm_names[tlsm];
    else
	return GT_("(invalid)");
}

e_sslmode tlsm_parse(const char *s) {
    for (int i = 0; i < TLSM_NAMESCOUNT; i++) {
	if (tlsm_names[i] // we may not have names for all options
		&& 0 == strcasecmp(tlsm_names[i], s))
	    return i;
    }
    return TLSM_INVALID;
}
