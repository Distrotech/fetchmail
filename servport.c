/** \file servport.c Resolve service name to port number.
 * \author Matthias Andree
 * \date 2005
 *
 * Copyright (C) 2005 by Matthias Andree
 * For license terms, see the file COPYING in this directory.
 */
#include "fetchmail.h"
#include "i18n.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

int servport(const char *service) {
    int port;
    unsigned long u;
    char *end;

    if (service == 0)
	return -1;

    /*
     * Check if the service is a number. If so, convert it.
     * If it isn't a number, call getservbyname to resolve it.
     */
    errno = 0;
    u = strtoul(service, &end, 10);
    if (errno || end[strspn(end, POSIX_space)] != '\0') {
	struct servent *se;

	/* hardcode kpop to port 1109 as per fetchmail(1)
	 * manual page, it's not a IANA registered service */
	if (strcmp(service, "kpop") == 0)
	    return 1109;

	se = getservbyname(service, "tcp");
	if (se == NULL) {
	    endservent();
	    goto err;
	} else {
	    port = ntohs(se->s_port);
	    endservent();
	}
    } else {
	if (u == 0 || u > 65535)
	    goto err;
	port = u;
    }

    return port;
err:
    report(stderr, GT_("Cannot resolve service %s to port.  Please specify the service as decimal port number.\n"), service);
    return -1;
}
/* end of servport.c */
