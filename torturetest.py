#!/usr/bin/env python

import sys, getopt, os, smtplib, commands, time

class TestSite:
    temp = "/usr/tmp/torturestest-%d" % os.getpid()

    def __init__(self, line):
        "Initialize site data from the external representation."
        (self.host, self.mailname, self.userid, self.password, \
                self.proto, self.options, self.capabilities, self.version, self.comment) = \
                line.strip().split(":")
        if not self.mailname:
            self.mailname = self.userid
        # Test results
        self.status = None
        self.output = None

    def allattrs(self):
        "Return a tuple consisting of alll this site's attributes."
        return (self.host, self.mailname, self.userid, self.password, \
                self.proto, self.options, self.capabilities, \
                self.version, self.comment)

    def __repr__(self):
        "Return the external representation of this site's data."
        return ":".join(self.allattrs())

    def prettyprint(self):
        "Prettyprint a site entry in human-readable form."
        return "Host: %s\n" \
              "Mail To: %s\n" \
              "Userid: %s\n" \
              "Password: %s\n" \
              "Protocol: %s\n" \
              "Options: %s\n" \
              "Capabilities: %s\n" \
              "Version: %s\n" \
              "Comment: %s\n" \
              % self.allattrs()

    def entryprint(self):
        "Print a .fetchmailrc entry corresponding to a site entry."
        return "poll %s-%s via %s with proto %s %s\n" \
               "   user %s there with password %s is esr here\n\n" \
               % (self.host,self.proto,self.host,self.proto,self.options,self.userid,self.password)

    def tableprint(self):
        "Print an HTML server-type table entry."
        return "<tr><td>%s: %s</td><td>%s</td>\n" \
               % (self.proto, self.comment, self.capabilities)

    def id(self):
        "Identify this site."
        rep = "%s %s at %s" % (self.proto, self.version, self.host)
        if self.capabilities:
            rep += " (" + self.capabilities + ")"
        if self.options:
            rep += " using " + self.options
        return rep

    def testmail(self):
        "Send test mail to the site."
        server = smtplib.SMTP("localhost")
        fromaddr = "esr@thyrsus.com"
        toaddr = "%s@%s" % (self.mailname, self.host)
        msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, toaddr))
        msg += "Test mail collected from %s.\n" % (self.id(),)
        server.sendmail(fromaddr, toaddr, msg)
        server.quit()

    def fetch(self):
        "Run a mail fetch on this site."
        try:
            ofp = open(TestSite.temp, "w")
            ofp.write(site.entryprint())
            ofp.close()
            (self.status, self.output) = commands.getstatusoutput("fetchmail -d0 -v -f - <%s"%TestSite.temp)
        finally:
            os.remove(TestSite.temp)

    def failed(self):
        "Did we have a test failure here?"
        return os.WIFEXITED(self.status) and os.WEXITSTATUS(self.status) > 1

    def explain(self):
        "Explain the status of the last test."
        if not os.WIFEXITED(self.status):
            return self.id() + ": abnormal termination\n"
        elif os.WEXITSTATUS(self.status) > 1:
            return self.id() + ": %d\n" % os.WEXITSTATUS(self.status) + self.output
        else:
            return self.id() + ": succeeded\n"

if __name__ == "__main__":
    # Start by reading in the sitelist
    ifp = open("testsites")
    sitelist = []
    linect = 0
    while 1:
        linect += 1
        line = ifp.readline()
        if not line:
            break
        elif line[0] in ("#", "\n"):
            continue
        else:
            try:
                sitelist.append(TestSite(line))
            except:
                print "Error on line %d" % linect
                sys.exit(0)

    (options, arguments) = getopt.getopt(sys.argv[1:], "dfp:tigvs")
    verbose = 0
    for (switch, value) in options:
        if switch == "-d":
            # Prettprint the sitelist
            map(lambda x: sys.stdout.write(x.prettyprint() + "%%\n"), sitelist)
            sys.exit(0)
        elif switch == "-f":
            # Dump the sitelist as a .fetchmailrc file
            map(lambda x: sys.stdout.write(x.entryprint()), sitelist)
            sys.exit(0)
        elif switch == "-p":
            # Probe a single site
            selected = []
            for site in sitelist:
                if `site`.find(value) > -1:
                    selected.append(site)
            sitelist = selected
            # Fall through
        elif switch == "-t":
            # Dump the sitelist in HTML table form
            map(lambda x: sys.stdout.write(x.tableprint()), sitelist)
            sys.exit(0)
        elif switch == "-i":
            # Dump the ids of the sitelist
            map(lambda x: sys.stdout.write(x.id() + "\n"), sitelist)
            sys.exit(0)
        elif switch == "-g":
            for site in sitelist:
                print "Sending test mail to " + site.id()
                site.testmail()
            # Send test mail to each site
            sys.stdout.write("Delaying to give the test mail time to land...")
            time.sleep(5)
            sys.stdout.write("here we go:\n")
            # Fall through
        elif switch == "-v":
            # Display the test output
            verbose = 1
        elif switch == "-s":
            # Dump version strings of all tested servers as a Python tuple
            print "(" + ",\n".join(map(lambda x: repr(x.version), filter(lambda x: x.version, sitelist))) + ")"
            sys.exit(0)

    # If no options, run the torture test
    try:
        failures = successes = 0
        os.system("fetchmail -q")
        for site in sitelist:
            print "Testing " + site.id()
            site.fetch()
            if verbose:
                print site.output
            if site.failed():
                failures += 1
            else:
                successes += 1

        # OK, summarize results
        print "\n%d successes and %d failures out of %d tests" \
              % (successes, failures, len(sitelist))

        if failures:
            print "Bad status was returned on the following sites:"
            for site in sitelist:
                if site.failed():
                    sys.stdout.write(site.explain() + "\n")
    except KeyboardInterrupt:
        print "Interrupted."

# end
