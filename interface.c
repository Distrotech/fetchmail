/*
 * interface.c -- implements fetchmail 'interface' and 'monitor' commands
 *
 * This module was implemented by George M. Sipe <gsipe@mindspring.com>
 * or <gsipe@acm.org> and is:
 *
 *	Copyright (c) 1996,1997 by George M. Sipe - ALL RIGHTS RESERVED
 *
 * This is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2, or (at your option) any later version.
 */

#ifdef linux

#include "config.h"
#include <stdio.h>
#include <string.h>
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "config.h"
#include "fetchmail.h"

typedef struct {
	struct in_addr addr, dstaddr, netmask;
	int rx_packets, tx_packets;
} ifinfo_t;

struct interface_pair_s {
	struct in_addr interface_address;
	struct in_addr interface_mask;
} *interface_pair;

static int _get_ifinfo_(int socket_fd, FILE *stats_file, const char *ifname,
		ifinfo_t *ifinfo)
/* get active network interface information - return non-zero upon success */
{
	int namelen = strlen(ifname);
	struct ifreq request;
	char *cp, buffer[256];

	/* initialize result */
	memset((char *) ifinfo, 0, sizeof(ifinfo_t));

	/* see if the interface is up */
	strcpy(request.ifr_name, ifname);
	if (ioctl(socket_fd, SIOCGIFFLAGS, &request) < 0)
		return(FALSE);
	if (!(request.ifr_flags & IFF_RUNNING))
		return(FALSE);

	/* get the IP address */
	strcpy(request.ifr_name, ifname);
	if (ioctl(socket_fd, SIOCGIFADDR, &request) < 0)
		return(FALSE);
	ifinfo->addr = ((struct sockaddr_in *) (&request.ifr_addr))->sin_addr;

	/* get the PPP destination IP address */
	strcpy(request.ifr_name, ifname);
	if (ioctl(socket_fd, SIOCGIFDSTADDR, &request) >= 0)
		ifinfo->dstaddr = ((struct sockaddr_in *)
					(&request.ifr_dstaddr))->sin_addr;

	/* get the netmask */
	strcpy(request.ifr_name, ifname);
	if (ioctl(socket_fd, SIOCGIFNETMASK, &request) >= 0)
		ifinfo->netmask = ((struct sockaddr_in *)
					(&request.ifr_netmask))->sin_addr;

	/* get the packet I/O counts */
	while (fgets(buffer, sizeof(buffer) - 1, stats_file)) {
		for (cp = buffer; *cp && *cp == ' '; ++cp);
		if (!strncmp(cp, ifname, namelen) &&
				cp[namelen] == ':') {
			cp += namelen + 1;
			sscanf(cp, "%d %*d %*d %*d %*d %d %*d %*d %*d %*d %*d",
				&ifinfo->rx_packets, &ifinfo->tx_packets);
			return(TRUE);
		}
	}
	return(FALSE);
}

static int get_ifinfo(const char *ifname, ifinfo_t *ifinfo)
{
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	FILE *stats_file = fopen("/proc/net/dev", "r");
	int result;

	if (socket_fd < 0 || !stats_file)
		result = FALSE;
	else
		result = _get_ifinfo_(socket_fd, stats_file, ifname, ifinfo);
	if (socket_fd >= 0)
		close(socket_fd);
	if (stats_file)
		fclose(stats_file);
	return(result);
}

void interface_parse(char *buf, struct hostdata *hp)
/* parse 'interface' specification */
{
	char *cp1, *cp2;

	/* find and isolate just the IP address */
	if (!(cp1 = strchr(buf, '/')))
		(void) error(PS_SYNTAX, 0, "missing IP interface address");
	*cp1++ = '\000';
	hp->interface = xstrdup(buf);

	/* find and isolate just the netmask */
	if (!(cp2 = strchr(cp1, '/')))
		cp2 = "255.255.255.255";
	else
		*cp2++ = '\000';

	/* convert IP address and netmask */
	hp->interface_pair = (struct interface_pair_s *)xmalloc(sizeof(struct interface_pair_s));
	if (!inet_aton(cp1, &hp->interface_pair->interface_address))
		(void) error(PS_SYNTAX, 0, "invalid IP interface address");
	if (!inet_aton(cp2, &hp->interface_pair->interface_mask))
		(void) error(PS_SYNTAX, 0, "invalid IP interface mask");
	/* apply the mask now to the IP address (range) required */
	hp->interface_pair->interface_address.s_addr &=
		hp->interface_pair->interface_mask.s_addr;
	return;
}

void interface_note_activity(struct hostdata *hp)
/* save interface I/O counts */
{
	ifinfo_t ifinfo;
	struct query *ctl;

	/* if not monitoring link, all done */
	if (!hp->monitor)
		return;

	/* get the current I/O stats for the monitored link */
	if (get_ifinfo(hp->monitor, &ifinfo))
		/* update this and preceeding host entries using the link
		   (they were already set during this pass but the I/O
		   count has now changed and they need to be re-updated)
		*/
		for (ctl = querylist; ctl; ctl = ctl->next) {
			if (!strcmp(hp->monitor, ctl->server.monitor))
				ctl->server.monitor_io =
					ifinfo.rx_packets + ifinfo.tx_packets;
			/* do NOT update host entries following this one */
			if (&ctl->server == hp)
				break;
		}

#ifdef	ACTIVITY_DEBUG
	(void) error(0, 0, "activity on %s -noted- as %d", 
		hp->monitor, hp->monitor_io);
#endif
}

int interface_approve(struct hostdata *hp)
/* return TRUE if OK to poll, FALSE otherwise */
{
	ifinfo_t ifinfo;

	/* check interface IP address (range), if specified */
	if (hp->interface) {
		/* get interface info */
		if (!get_ifinfo(hp->interface, &ifinfo)) {
			(void) error(0, 0, "skipping poll of %s, %s down",
				hp->pollname, hp->interface);
			return(FALSE);
		}
		/* check the IP address (range) */
		if ((ifinfo.addr.s_addr &
				hp->interface_pair->interface_mask.s_addr) !=
				hp->interface_pair->interface_address.s_addr) {
			(void) error(0, 0,
				"skipping poll of %s, %s IP address excluded",
				hp->pollname, hp->interface);
			return(FALSE);
		}
	}

	/* if not monitoring link, all done */
	if (!hp->monitor)
		return(TRUE);

#ifdef	ACTIVITY_DEBUG
	(void) error(0, 0, "activity on %s checked as %d", 
		hp->monitor, hp->monitor_io);
#endif
	/* if monitoring, check link for activity if it is up */
	if (get_ifinfo(hp->monitor, &ifinfo) &&
			hp->monitor_io == ifinfo.rx_packets +
				ifinfo.tx_packets) {
		(void) error(0, 0, "skipping poll of %s, %s inactive",
			hp->pollname, hp->monitor);
		return(FALSE);
	}

	return(TRUE);
}
#endif /* linux */
