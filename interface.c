/*
 * interface.c -- implements fetchmail 'interface' and 'monitor' commands
 *
 * This module was implemented by George M. Sipe <gsipe@mindspring.com>
 * or <gsipe@acm.org> and is:
 *
 *	Copyright (c) 1996 by George M. Sipe - ALL RIGHTS RESERVED
 *
 * This is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2, or (at your option) any later version.
 */

#ifdef	linux

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/netdevice.h>
#include "fetchmail.h"

static struct in_addr interface_address;
static struct in_addr interface_mask;

static int monitor_io = 0;

typedef struct {
	struct in_addr addr, dstaddr, netmask;
	int rx_packets, tx_packets;
} ifinfo_t;

/* Get active network interface information.  Return non-zero upon success. */

static int _get_ifinfo_(int socket_fd, FILE *stats_file, const char *ifname,
		ifinfo_t *ifinfo)
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
		result = -1;
	else
		result = _get_ifinfo_(socket_fd, stats_file, ifname, ifinfo);
	if (socket_fd >= 0)
		close(socket_fd);
	if (stats_file)
		fclose(stats_file);
	return(result);
}

/* Parse 'interface' specification. */

void interface_parse(void)
{
	int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	char *cp1, *cp2;
	struct ifreq request;

	/* in the event we point to a null string, make pointer null */
	if (interface && !*interface)
		interface = NULL;
	if (monitor && !*monitor)
		monitor = NULL;

	/* if no interface specification present, all done */
	if (!interface)
		return;

	/* find and isolate just the IP address */
	if (!(cp1 = strchr(interface, '/')))
		(void) error(PS_SYNTAX, 0, "missing IP interface address");
	*cp1++ = '\000';

	/* validate specified interface exists */
	strcpy(request.ifr_name, interface);
	if (ioctl(socket_fd, SIOCGIFFLAGS, &request) < 0)
		(void) error(PS_SYNTAX, 0, "no such interface device '%s'",
			interface);
	close(socket_fd);

	/* find and isolate just the netmask */
	if (!(cp2 = strchr(cp1, '/')))
		cp2 = "255.255.255.255";
	else
		*cp2++ = '\000';

	/* convert IP address and netmask */
	if (!inet_aton(cp1, &interface_address))
		(void) error(PS_SYNTAX, 0, "invalid IP interface address");
	if (!inet_aton(cp2, &interface_mask))
		(void) error(PS_SYNTAX, 0, "invalid IP interface mask");
	/* apply the mask now to the IP address (range) required */
	interface_address.s_addr &= interface_mask.s_addr;
	return;
}

/* Save interface I/O counts. */

void interface_note_activity(void)
{
	ifinfo_t ifinfo;

	/* get the current I/O stats for the monitored link */
	if (monitor && get_ifinfo(monitor, &ifinfo))
		monitor_io = ifinfo.rx_packets + ifinfo.tx_packets;
}

/* Return TRUE if OK to poll, FALSE otherwise. */

int interface_approve(void)
{
	ifinfo_t ifinfo;

	/* check interface IP address (range), if specified */
	if (interface) {
		/* get interface info */
		if (!get_ifinfo(interface, &ifinfo)) {
			(void) error(0, 0, "skipping poll, %s down",
				interface);
			return(FALSE);
		}
		/* check the IP address (range) */
		if ((ifinfo.addr.s_addr & interface_mask.s_addr) !=
				interface_address.s_addr) {
			(void) error(0, 0,
			   "skipping poll, %s IP address excluded",
			   interface);
			return(FALSE);
		}
	}

	/* if monitoring, check link for activity if it is up */
	if (monitor && get_ifinfo(monitor, &ifinfo) &&
			monitor_io == ifinfo.rx_packets + ifinfo.tx_packets) {
		(void) error(0, 0, "skipping poll, %s inactive", monitor);
		return(FALSE);
	}

	return(TRUE);
}
#endif	/* linux */
