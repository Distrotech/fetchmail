#!/usr/bin/env python2
#
# Python translation of fetchmail.
# Reads configuration from .fetchmailpyrc rather than .fetchmailrc
#
# Features removed:
# 1. Support for multiple usernames per UID.
# 2. Repolling on a changed rc file.
# 3. It's no longer possible to specify site parameters from the command line.

VERSION = "X0.1"

import os, sys, getpass, pwd, getopt, stat

# fetchmail return status codes 
PS_SUCCESS	= 0	# successful receipt of messages
PS_NOMAIL       = 1	# no mail available
PS_SOCKET	= 2	# socket I/O woes
PS_AUTHFAIL	= 3	# user authorization failed
PS_PROTOCOL	= 4	# protocol violation
PS_SYNTAX	= 5	# command-line syntax error
PS_IOERR	= 6	# bad permissions on rc file
PS_ERROR	= 7	# protocol error
PS_EXCLUDE	= 8	# client-side exclusion error
PS_LOCKBUSY	= 9	# server responded lock busy
PS_SMTP         = 10      # SMTP error
PS_DNS		= 11	# fatal DNS error
PS_BSMTP	= 12	# output batch could not be opened
PS_MAXFETCH	= 13	# poll ended by fetch limit
PS_SERVBUSY	= 14	# server is busy
PS_IDLETIMEOUT	= 15	# timeout on imap IDLE
# leave space for more codes
PS_UNDEFINED	= 23	# something I hadn't thought of
PS_TRANSIENT	= 24	# transient failure (internal use)
PS_REFUSED	= 25	# mail refused (internal use)
PS_RETAINED	= 26	# message retained (internal use)
PS_TRUNCATED	= 27	# headers incomplete (internal use)

# output noise level
O_SILENT	= 0	# mute, max squelch, etc.
O_NORMAL	= 1	# user-friendly
O_VERBOSE	= 2	# chatty
O_DEBUG		= 3	# prolix
O_MONITOR	= O_VERBOSE

# magic port numbers
SMTP_PORT	= 25
KPOP_PORT	= 1109
SIMAP_PORT	= 993
SPOP3_PORT	= 995

def DOTLINE(s):
    return (s[0] == '.' and (s[1]=='\r' or s[1]=='\n' or s[1]=='\0'))

# Error classes
class TransactionError(Exception):
    pass
class GeneralError(Exception):
    pass
class ProtocolError(Exception):
    pass

class proto_pop2:
    "POP2 protocol methods"
    def __init__(self, ctl):
        name = 'POP2'
        service = 'pop2'
        sslservice = 'pop2'
        port = 109
        sslport = 109
        peek_capable = False
        tagged = False
        delimited = False
        repoll = False
        # Internal
        pound_arg = -1
        equal_arg = -1

    def ack(sock):
        self.pound_arg = self.equal_arg = -1
        buf = gen_recv(sock)
        if buf[0] == "#":
            pass
        elif buf[0] == "#":
            pound_arg = int(buf[1:])
        elif buf[0] == '=':
            equal_arg = int(buf[1:])
        elif buf[0] == '-':
            raise GeneralError()
        else:
            raise ProtocolError()
        return buf

    def getauth(sock, ctl):
        shroud = ctl.password
        status = gen_transact(sock, \
                              "HELO %s %s" % (ctl.remotename, ctl.password))
        shroud = None
        return status

    def getrange(sock, ctl, folder):
        if folder:
          ok = gen_transact(sock, "FOLD %s" % folder)
          if pound_arg == -1:
              raise GeneralError()
        else:
            # We should have picked up a count of messages in the user's
            # default inbox from the pop2_getauth() response. 
            #
            # Note: this logic only works because there is no way to select
            # both the unnamed folder and named folders within a single
            # fetchmail run.  If that assumption ever becomes invalid, the
            # pop2_getauth code will have to stash the pound response away
            # explicitly in case it gets stepped on.
          if pound_arg == -1:
              raise GeneralError()
        return(pound_arg, -1, -1)

    def fetch(sock, ctl, number):
        # request nth message
        ok = gen_transact(sock, "READ %d", number);
        gen_send(sock, "RETR");
        return equal_arg;

    def trail(sock, ctl, number):
        # send acknowledgement for message data
        if ctl.keep:
            return gen_transact(sock, "ACKS")
        else:
            return gen_transact(sock, "ACKD")

    def logout(sock, ctl):
        # send logout command
        return gen_transact(sock, "QUIT")

class proto_pop3:
    "POP3 protocol methods"
    def __init__(self, ctl):
        name = 'POP3'
        service = 'pop2'
        sslservice = 'pop2'
        port = 110
        sslport = 995
        peek_capable = not ctl.fetchall
        tagged = False
        delimited = True
        retry = False
        # Internal
        has_gssapi = FALSE
        has_kerberos = FALSE
        has_cram = FALSE
        has_otp = FALSE
        has_ssl = FALSE

        # FIXME: fill in POP3 logic

class hostdata:
    "Per-mailserver control data."

    # rc file data
    pollname = None		# poll label of host
    via = None			# "true" server name if non-NULL
    akalist = []		# server name first, then akas
    localdomains = []		# list of pass-through domains
    protocol = None		# protocol type
    netsec = None		# IPv6 security request
    port = None			# TCP/IP service port number (name in IPV6)
    interval = 0		# cycles to skip between polls
    authenticate = 'password'	# authentication mode to try
    timeout = 300		# inactivity timout in seconds
    envelope = None		# envelope address list header
    envskip = 0			# skip to numbered envelope header
    qvirtual = None		# prefix removed from local user id
    skip = False		# suppress poll in implicit mode?
    dns	= True			# do DNS lookup on multidrop?
    uidl = False		# use RFC1725 UIDLs?
    sdps = False		# use Demon Internet SDPS *ENV
    checkalias = False     	# resolve aliases by comparing IPs?
    principal = None		# Kerberos principal for mail service
    esmtp_name = None		# ESMTP AUTH information
    esmtp_password = None

    # Only used under Linux
    interface = None
    monitor = None
    monitor_io = 0
    #struct interface_pair_s *interface_pair

    plugin = None
    plugout = None

    # computed for internal use
    base_protocol = None	# relevant protocol method table
    poll_count = 0		# count of polls so far
    queryname = None		# name to attempt DNS lookup on
    truename = None		# "true name" of server host
    trueaddr = None             # IP address of truename, as char
    lead_server = None		# ptr to lead query for this server
    esmtp_options = []		# ESMTP option list

    def is_mailbox_protocol(self):
         # We need to distinguish between mailbox and mailbag protocols.
         # Under a mailbox protocol we're pulling mail for a speecific user.
         # Under a mailbag protocol we're fetching mail for an entire domain.
         return self.protocol != proto_etrn

class query:
    "All the parameters of a fetchmail query."
    # mailserver connection controls
    server = None

    # per-user data
    localnames = [] 		# including calling user's name
    wildcard = False		# should unmatched names be passed through
    remotename = None		# remote login name to use
    password = None		# remote password to use
    mailboxes = []		# list of mailboxes to check

    # per-forwarding-target data
    smtphunt = []		# list of SMTP hosts to try forwarding to
    domainlist = []		# domainlist to fetch from
    smtpaddress = None		# address to force in RCPT TO 
    smtpname = None		# full RCPT TO name, including domain
    antispam = []		# list of listener's antispam response
    mda = None			# local MDA to pass mail to
    bsmtp = None		# BSMTP output file
    listener = 'SMTP'		# what's the listener's wire protocol?
    preconnect = None		# pre-connection command to execute
    postconnect = None		# post-connection command to execute

    # per-user control flags
    keep = False		# if TRUE, leave messages undeleted
    fetchall = False		# if TRUE, fetch all (not just unseen)
    flush = False		# if TRUE, delete messages already seen
    rewrite = False		# if TRUE, canonicalize recipient addresses
    stripcr = False		# if TRUE, strip CRs in text
    forcecr = False		# if TRUE, force CRs before LFs in text
    pass8bits = False		# if TRUE, ignore Content-Transfer-Encoding
    dropstatus = False		# if TRUE, drop Status lines in mail
    dropdelivered = False	# if TRUE, drop Delivered-To lines in mail
    mimedecode = False		# if TRUE, decode MIME-armored messages
    idle = False		# if TRUE, idle after each poll
    limit = 0			# limit size of retrieved messages
    warnings = 3600		# size warning interval
    fetchlimit = 0		# max # msgs to get in single poll
    batchlimit = 0		# max # msgs to pass in single SMTP session
    expunge = 1			# max # msgs to pass between expunges
    use_ssl = False		# use SSL encrypted session
    sslkey = None		# optional SSL private key file
    sslcert = None		# optional SSL certificate file
    sslproto = None		# force usage of protocol (ssl2|ssl3|tls1) - defaults to ssl23
    sslcertpath = None		# Trusted certificate directory for checking the server cert
    sslcertck = False		# Strictly check the server cert.
    sslfingerprint = None	# Fingerprint to check against
    properties = []		# passthrough properties for extensions
    tracepolls = False		# if TRUE, add poll trace info to Received

    # internal use -- per-poll state
    active = False		# should we actually poll this server?
    destaddr = None		# destination host for this query
    errcount = 0		# count transient errors in last pass
    authfailcount = 0		# count of authorization failures
    wehaveauthed = 0		# We've managed to logon at least once!
    wehavesentauthnote = 0	# We've sent an authorization failure note
    wedged = 0			# wedged by auth failures or timeouts?
    smtphost = None		# actual SMTP host we connected to
    smtp_socket = -1		# socket descriptor for SMTP connection
    uid = 0			# UID of user to deliver to
    skipped = []		# messages skipped on the mail server
    oldsaved = []
    newsaved = []
    oldsavedend = []
    lastid = None		# last Message-ID seen on this connection
    thisid = None		# Message-ID of current message

    # internal use -- per-message state
    mimemsg = 0			# bitmask indicating MIME body-type
    digest = None

    def dump(self):
	print "Options for retrieving from %s@%s:" \
              % (self.remotename, self.server.pollname)
        if self.server.via and self.server.server.is_mailbox_protocol():
	    print "  Mail will be retrieved via %s" % self.server.via
	if self.server.interval:
	    print "  Poll of this server will occur every %d intervals." \
		   % self.server.interval;
	if self.server.truename:
	    print "  True name of server is %s." % self.server.truename
	if self.server.skip || outlevel >= O_VERBOSE:
            if self.server.skip:
                print "  Will not be queried when no host is specified."
            else:
                print "  Will not be queried when no host is specified."
	if self.server.authenticate not in ('KERBEROS', 'GSSAPI', 'SSH'):
            if not self.password:
		print "  Password will be prompted for."
	    else if outlevel >= O_VERBOSE:
                if self.server.protocol == proto_apop:
		    print "  APOP secret = \"%s\"." % self.password
		elif self.server.protocol == proto_rpop:
		    print "  RPOP id = \"%s\"." % self.password
		else
		    print "  Password = \"%s\"." % self.password

	if self.server.protocol == proto_pop3 \
	    	and self.server.port == KPOP_PORT \
            	and self.server.authenticate.startswith("Kerberos"):
            sys.stdout.write("  Protocol is KPOP with %s authentication" \
                  % self.server.authenticate)
	else
	    sys.stdout.write("  Protocol is %s" % self.server.protocol.name)
        if ipv6:
            if self.server.port:
                sys.stdout.write(" (using service %s)" % self.server.port)
            if (self.server.netsec)
                sys.stdout.write(" (using network security options %s)" % self.server.netsec)
        else:
            if self.server.port:
                sys.stdout.write(" (using port %d)" % self.server.port)
            else if outlevel >= O_VERBOSE:
                sys.stdout.write(" (using default port)")
	if self.server.uidl and self.server.is_mailbox.protocol())
	    sys.stdout.write(" (forcing UIDL use)")
        sys.stdout.write("\n")
        print {
        None :       "  All available authentication methods will be tried.",
        'password' :    "  Password authentication will be forced.",
        'NTLM' :        "  NTLM authentication will be forced.",
        'OTP' :         "  OTP authentication will be forced.",
        'CRAM-MD5'      "  CRAM-MD5 authentication will be forced.",
        'GSSAPI' :      "  GSSAPI authentication will be forced.",
        'Kerberos V4' : "  Kerberos V4 authentication will be forced.",
        'Kerberos V5' : "  Kerberos V5 authentication will be forced.",
        'ssh' :         "  End-to-end encryption will be assumed.",
        }[self.server.authenticate]

        if self.server.principal:
	    print "  Mail service principal is: %s" % self.server.principal
	if self.use_ssl:
	    print "  SSL encrypted sessions enabled."
	if self.sslproto:
	    print "  SSL protocol: %s." % self.sslproto;
	if self.sslcertck:
	    print "  SSL server certificate checking enabled."
	    if self.sslcertpath:
		print "  SSL trusted certificate directory: %s" % self.sslcertpath;
	if self.sslfingerprint:
		print "  SSL key fingerprint (checked against the server key): %s" % self.sslfingerprint;
	if self.server.timeout > 0:
	    print "  Server nonresponse timeout is %d seconds" % self.server.timeout;
	if self.server.is_mailbox_protocol(): 
	    if not self.mailboxes.id:
		print "  Default mailbox selected."
	    else
		print "  Selected mailboxes are: ", ", ".join(self.mailboxes)
            flagarray = (
                ('fetchall', 
                 "%s messages will be retrieved (--all %s)."
                 "All", "Only new")
                ('keep', 
                 "  Fetched messages %s be kept on the server (--keep %s)."
                 "will", "will not")
                ('flush',
                "  Old messages %s be flushed before message retrieval (--flush %s).",
                 "will", "will not")
                ('rewrite',
                "  Rewrite of server-local addresses is %s (norewrite %s).",
                 "enabled", "disabled")
                ('stripcr',
                "  Carriage-return stripping is %s (stripcr %s).",
                 "enabled", "disabled")
                ('forcecr',
                "  Carriage-return forcing is %s (forcecr %s).",
                 "enabled", "disabled")
                ('pass8bits',
                 "  Interpretation of Content-Transfer-Encoding is %s (pass8bits %s).",
                 "enabled", "disabled")
                ('mimedecode',
                 "  MIME decoding is %s (mimedecode %s).",
                 "enabled", "disabled")
                ('idle',
                 "  Idle after poll is %s (idle %s).",
                 "enabled", "disabled")
                ('dropstatus',
                 "  Nonempty Status lines will be %s (dropstatus %s)",
                 "discarded", "kept")
                ('dropdelivered',
                 "  Delivered-To lines will be %s (dropdelivered %s)",
                 "discarded", "kept")
                )
            for (attr, template, on, off) in flagarray:
                flag = getattr(self, att)
                if flag:
                    onoff1 = on
                    onoff2 = "on"
                else:
                    onoff1 = off
                    onoff2 = "off"
                print template % (onoff1, onoff2)
	    if self.limit:
	    {
		if NUM_NONZERO(self.limit):
		    print "  Message size limit is %d octets (--limit %d)." % 
			   self.limit, self.limit);
		else if outlevel >= O_VERBOSE:
		    print "  No message size limit (--limit 0)."
		if run.poll_interval > 0:
		    print "  Message size warning interval is %d seconds (--warnings %d)." % 
			   self.warnings, self.warnings);
		else if outlevel >= O_VERBOSE:
		    print "  Size warnings on every poll (--warnings 0)."
	    }
	    if NUM_NONZERO(self.fetchlimit):
		print "  Received-message limit is %d (--fetchlimit %d)."),
		       self.fetchlimit, self.fetchlimit);
	    else if outlevel >= O_VERBOSE:
		print "  No received-message limit (--fetchlimit 0)."
	    if NUM_NONZERO(self.batchlimit):
		print "  SMTP message batch limit is %d." % self.batchlimit);
	    else if outlevel >= O_VERBOSE:
		print "  No SMTP message batch limit (--batchlimit 0)."
	    if MAILBOX_PROTOCOL(ctl):
	    {
		if NUM_NONZERO(self.expunge):
		    print "  Deletion interval between expunges forced to %d (--expunge %d)." % self.expunge, self.expunge);
		else if outlevel >= O_VERBOSE:
		    print "  No forced expunges (--expunge 0)."
	    }
	}
	else	/* ODMR or ETRN */
	{
	    struct idlist *idp;

	    print "  Domains for which mail will be fetched are:"
	    for (idp = self.domainlist; idp; idp = idp.next:
	    {
		printf(" %s", idp.id);
		if not idp.val.status.mark:
		    print " (default)"
	    }
	    printf("");
	}
	if self.bsmtp:
	    print "  Messages will be appended to %s as BSMTP" % visbuf(self.bsmtp
	else if self.mda and MAILBOX_PROTOCOL(ctl):
	    print "  Messages will be delivered with \"%s\"." % visbuf(self.mda
	else
	{
	    struct idlist *idp;

	    if self.smtphunt:
	    {
		print "  Messages will be %cMTP-forwarded to:" % 
		       self.listener);
		for (idp = self.smtphunt; idp; idp = idp.next:
		{
		    printf(" %s", idp.id);
		    if not idp.val.status.mark:
			print " (default)"
		}
		printf("");
	    }
	    if self.smtpaddress:
		print "  Host part of MAIL FROM line will be %s"),
		       self.smtpaddress);
	    if self.smtpname:
		print "  Address to be put in RCPT TO lines shipped to SMTP will be %s"),
		       self.smtpname);
	}
	if MAILBOX_PROTOCOL(ctl):
	{
		if self.antispam != (struct idlist *)NULL:
		{
		    struct idlist *idp;

		    print "  Recognized listener spam block responses are:"
		    for (idp = self.antispam; idp; idp = idp.next:
			printf(" %d", idp.val.status.num);
		    printf("");
		}
		else if outlevel >= O_VERBOSE:
		    print "  Spam-blocking disabled"
	}
	if self.preconnect:
	    print "  Server connection will be brought up with \"%s\"."),
		   visbuf(self.preconnect
	else if outlevel >= O_VERBOSE:
	    print "  No pre-connection command."
	if self.postconnect:
	    print "  Server connection will be taken down with \"%s\"."),
		   visbuf(self.postconnect
	else if outlevel >= O_VERBOSE:
	    print "  No post-connection command."
	if MAILBOX_PROTOCOL(ctl)) {
		if !self.localnames:
		    print "  No localnames declared for this host."
		else
		{
		    struct idlist *idp;
		    int count = 0;

		    for (idp = self.localnames; idp; idp = idp.next:
			++count;

		    if count > 1 || self.wildcard:
			print "  Multi-drop mode: "
		    else
			print "  Single-drop mode: "

		    print "%d local name(s) recognized." % count);
		    if outlevel >= O_VERBOSE:
		    {
			for (idp = self.localnames; idp; idp = idp.next:
			    if idp.val.id2:
				printf("\t%s . %s", idp.id, idp.val.id2);
			    else
				printf("\t%s", idp.id);
			if self.wildcard:
			    fputs("\t*", stdout);
		    }

		    if count > 1 || self.wildcard:
		    {
			print "  DNS lookup for multidrop addresses is %s."),
			       self.server.dns ? GT_("enabled") : GT_("disabled"
			if self.server.dns:
			{
			    print "  Server aliases will be compared with multidrop addresses by "
	       		    if self.server.checkalias:
				print "IP address."
			    else
				print "name."
			}
			if self.server.envelope == STRING_DISABLED:
			    print "  Envelope-address routing is disabled"
			else
			{
			    print "  Envelope header is assumed to be: %s"),
				   self.server.envelope ? self.server.envelope:GT_("Received"
			    if self.server.envskip > 1 || outlevel >= O_VERBOSE:
				print "  Number of envelope header to be parsed: %d"),
				       self.server.envskip);
			    if self.server.qvirtual:
				print "  Prefix %s will be removed from user id"),
				       self.server.qvirtual);
			    else if outlevel >= O_VERBOSE) 
				print "  No prefix stripping"
			}

			if self.server.akalist:
			{
			    struct idlist *idp;

			    print "  Predeclared mailserver aliases:"
			    for (idp = self.server.akalist; idp; idp = idp.next:
				printf(" %s", idp.id);
			    putchar('');
			}
			if self.server.localdomains:
			{
			    struct idlist *idp;

			    print "  Local domains:"
			    for (idp = self.server.localdomains; idp; idp = idp.next:
				printf(" %s", idp.id);
			    putchar('');
			}
		    }
		}
	}
#if defined(linux) || defined(__FreeBSD__:
	if self.server.interface:
	    print "  Connection must be through interface %s." % self.server.interface);
	else if outlevel >= O_VERBOSE:
	    print "  No interface requirement specified."
	if self.server.monitor:
	    print "  Polling loop will monitor %s." % self.server.monitor);
	else if outlevel >= O_VERBOSE:
	    print "  No monitor interface specified."
#endif

	if self.server.plugin:
	    print "  Server connections will be made via plugin %s (--plugin %s)." % self.server.plugin, self.server.plugin);
	else if outlevel >= O_VERBOSE:
	    print "  No plugin command specified."
	if self.server.plugout:
	    print "  Listener connections will be made via plugout %s (--plugout %s)." % self.server.plugout, self.server.plugout);
	else if outlevel >= O_VERBOSE:
	    print "  No plugout command specified."

	if self.server.protocol > P_POP2 and MAILBOX_PROTOCOL(ctl):
	{
	    if !self.oldsaved:
		print "  No UIDs saved from this host."
	    else
	    {
		struct idlist *idp;
		int count = 0;

		for (idp = self.oldsaved; idp; idp = idp.next:
		    ++count;

		print "  %d UIDs saved." % count);
		if outlevel >= O_VERBOSE:
		    for (idp = self.oldsaved; idp; idp = idp.next:
			printf("\t%s", idp.id);
	    }
	}

        if self.tracepolls:
            print "  Poll trace information will be added to the Received header."
        else if outlevel >= O_VERBOSE:
            print "  No poll trace information will be added to the Received header.."

	if self.properties:
	    print "  Pass-through properties \"%s\"." % self.properties



if __name__ == '__main__':
    # C version queried FETCHMAILUSER, then USER, then LOGNAME.
    # Order here is FETCHMAILUSER, LOGNAME, USER, LNAME and USERNAME.
    user = os.getenv("FETCHMAILUSER") or getpass.getuser()
    for injector in ("QMAILINJECT", "NULLMAILER_FLAGS"):
        if os.getenv(injector):
            print >>sys.stderr, \
                  ("fetchmail: The %s environment variable is set.\n"
                  "This is dangerous, as it can make qmail-inject or qmail's\n"
                  "sendmail wrapper tamper with your From or Message-ID "
                  "headers.\n"
                  "Try 'env %s= fetchmail YOUR ARGUMENTS HERE'\n") % (injector, injector)
            sys.exit(PS_UNDEFINED)

    # Figure out who calling user is and where the run-control file is.
    # C version handled multiple usernames per PID; this doesn't.
    try:
        pwp = pwd.getpwuid(os.getuid())
    except:
        print >>sys.stderr, "You don't exist.  Go away."
        sys.exit(PS_UNDEFINED)
    home = os.getenv("HOME") or pwp.pw_dir
    fmhome = os.getenv("FETCHMAILHOME") or home
    rcfile = os.path.join(fmhome, ".fetchmailpyrc")
    idfile = os.path.join(fmhome, ".fetchids")

    cmdhelp = \
	"usage:  fetchmail [options] [server ...]\n" \
	"  Options are as follows:\n" \
	"  -?, --help        display this option help\n" \
	"  -V, --version     display version info\n" \
	"  -c, --check       check for messages without fetching\n" \
	"  -s, --silent      work silently\n" \
	"  -v, --verbose     work noisily (diagnostic output)\n" \
	"  -d, --daemon      run as a daemon once per n seconds\n" \
	"  -N, --nodetach    don't detach daemon process\n" \
	"  -q, --quit        kill daemon process\n" \
	"  -f, --fetchmailrc specify alternate run control file\n" \
	"  -a, --all         retrieve old and new messages\n" \
	"  -k, --keep        save new messages after retrieval\n" \
	"  -F, --flush       delete old messages from server\n"

    # Now time to parse the command line
    try:
        (options, arguments) = getopt.getopt(sys.argv[1:],
                                             "?Vcsvd:NqfakF",
                                             ("help",
                                              "version",
                                              "check",
                                              "silent",
                                              "verbose",
                                              "daemon",
                                              "nodetach",
                                              "quit",
                                              "fetchmailrc",
                                              "all",
                                              "keep",
                                              "flush",
                                              ))
    except getopt.GetoptError:
        print cmdhelp
        sys.exit(PS_SYNTAX)
    versioninfo = checkonly = silent = nodetach = quitmode = False
    fetchall = keep = flutch = False 
    outlevel = O_NORMAL
    poll_interval = -1
    for (switch, val) in options:
	if switch in ("-?", "--help"):
	    print cmdhelp
            sys.exit(0)
	elif switch in ("-V", "--version"):
	    versioninfo = True
	elif switch in ("-c", "--check"):
	    checkonly = True
	elif switch in ("-s", "--silent"):
	    outlevel = O_SILENT
	elif switch in ("-v", "--verbose"):
            if outlevel == O_VERBOSE:
                outlevel = O_DEBUG
            else:
                outlevel = O_VERBOSE
	elif switch in ("-d", "--daemon"):
            poll_interval = int(val)
	elif switch in ("-N", "--nodetach"):
	    outlevel = O_SILENT
	elif switch in ("-q", "--quitmode"):
	    quitmode = True
	elif switch in ("-f", "--fetchmailrc"):
	    rcfile = val
	elif switch in ("-a", "--all"):
	    fetchall = True
	elif switch in ("-k", "--keep"):
	    keep = True
	elif switch in ("-F", "--flush"):
	    flush = True

        if versioninfo:
            print "This is fetchmail release", VERSION
            os.system("uname -a")

        # avoid parsing the config file if all we're doing is killing a daemon
        fetchmailrc = {}
        if not quitmode or len(sys.argv) != 2:
            # user probably supplied a configuration file, check security
            if os.path.exists(rcfile):
                # the run control file must have the same uid as the
                # REAL uid of this process, it must have permissions
                # no greater than 600, and it must not be a symbolic
                # link.  We check these conditions here.
                try:
                    st = os.lstat(rcfile)
                except IOError:
                    sys.exit(PS_IOERR)
                if not versioninfo:
                    if not stat.S_ISREG(st.st_mode):
                            print >>sys.stderr, \
                                  "File %s must be a regular file." % pathname;
                            sys.exit(PS_IOERR);

                    if st.st_mode & 0067:
                            print >>sys.stderr, \
                                  "File %s must have no more than -rwx--x--- (0710) permissions." % pathname;
                            sys.exit(PS_IOERR);
            # time to read the configuration
            if rcfile == '-':
                ifp = sys.stdin
            elif os.path.exists(rcfile):
                ifp = file(rcfile)
            try:
                exec ifp in globals()
            except SyntaxError:
                print >>sys.stderr, \
                      "File %s is ill-formed." % pathname;
                sys.exit(PS_SYNTAX);
            ifp.close()
            # generate a default configuration if user did not supply one
            if not fetchmailrc:
                fetchmailrc = {
                    'poll_interval': 300,
                    "logfile": None,
                    "idfile": idfile,
                    "postmaster": "esr",
                    'bouncemail': True,
                    'spambounce': False,
                    "properties": "",
                    'invisible': False,
                    'showdots': False,
                    'syslog': False,
                    'servers': []
                    }
                for site in arguments:
                    fetchmailrc['servers'].append({
                        "pollname" : site,
                        'active' : False,
                        "via" : None,
                        "protocol" : "IMAP",
                        'port' : 0,
                        'timeout' : 300,
                        'interval' : 0,
                        "envelope" : "Received",
                        'envskip' : 0,
                        "qvirtual" : None,
                        "auth" : "any",
                        'dns' : True,
                        'uidl' : False,
                        "aka" : [],
                        "localdomains" : [],
                        "interface" : None,
                        "monitor" : None,
                        "plugin" : None,
                        "plugout" : None,
                        "principal" : None,
                        'tracepolls' : False,
                        'users' :  [
                            {
                                "remote" : user,
                                "password" : None,
                                'localnames' : [user],
                                'fetchall' : False,
                                'keep' : False,
                                'flush' : False,
                                'rewrite' : True,
                                'stripcr' : True,
                                'forcecr' : False,
                                'pass8bits' : False,
                                'dropstatus' : False,
                                'dropdelivered' : False,
                                'mimedecode' : False,
                                'idle' : False,
                                "mda" : "/usr/bin/procmail -d %T",
                                "bsmtp" : None,
                                'lmtp' : False,
                                "preconnect" : None,
                                "postconnect" : None,
                                'limit' : 0,
                                'warnings' : 3600,
                                'fetchlimit' : 0,
                                'batchlimit' : 0,
                                'expunge' : 0,
                                "properties" : None,
                                "smtphunt" : ["localhost"],
                                "fetchdomains" : [],
                                "smtpaddress" : None,
                                "smtpname" : None,
                                'antispam' : '',
                                "mailboxes" : [],
                            }
                            ]
                    })
            if poll_interval != -1: 
                fetchmailrc['poll_interval'] = poll_interval
            # now turn the configuration into control structures

