#!/usr/bin/env python

import sys, getopt, os, smtplib, commands

class TestSite:
    temp = "/usr/tmp/torturestest-%d" % os.getpid()

    def __init__(self, line):
        "Initialize site data from the external representation."
        (self.host, self.userid, self.password, \
                self.proto, self.options, self.version, self.comment) = \
                line.strip().split(":")
        # Test results
        self.status = None
        self.output = None

    def allattrs(self):
        "Return a tuple consisting of alll this site's attributes."
        return (self.host, self.userid, self.password, \
                         self.proto, self.options, self.version, self.comment)

    def __repr__(self):
        "Return the external representation of this site's data."
        return ":".join(self.allattrs())

    def prettyprint(self):
        "Prettyprint a site entry in human-readable form."
        return "Host: %s\n" \
              "Userid: %s\n" \
              "Password: %s\n" \
              "Protocol: %s\n" \
              "Optiond: %s\n" \
              "Version: %s\n" \
              "Comment: %s\n" \
              % self.allattrs()

    def entryprint(self):
        "Print a .fetchmailrc entry corresponding to a site entry."
        return "poll %s-%s  via %s with proto %s\n" \
               "   user %s there with password %s is esr here\n\n" \
               % (self.host,self.proto,self.host,self.proto,self.userid,self.password)

    def tableprint(self):
        "Print an HTML server-type table entry."
        return "<tr><td>%s %s</td><td>%s</td><td>%s</td></tr>\n" \
               % (self.proto, self.version, self.options, self.comment)

    def id(self):
        "Identify this site."
        return "%s %s at %s" % (self.proto, self.version, self.host)

    def testmail(self):
        "Send test mail to the site."
        server = smtplib.SMTP("localhost")
        fromaddr = "esr@thyrsus.com"
        toaddr = "%s@%s" % (self.userid, self.host)
        msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, toaddr))
        msg += "Test mail collected from %s.\n" % (toaddr, self.id())
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
        return os.WIFEXITED(self.status) or os.WEXITSTATUS(self.status) > 1

    def explain(self):
        "Explain the status of the last test."
        if not os.WIFEXITED(self.status):
            return self.id() + ": abnormal termination\n"
        elif os.WEXITSTATUS(self.status) > 1:
            return self.id() + ": %d\n" % os.WEXITSTATUS(status) + self.output

if __name__ == "__main__":
    # Start by reading in the sitelist
    ifp = open("testsites")
    sitelist = []
    while 1:
        line = ifp.readline()
        if not line:
            break
        elif line[0] in ("#", "\n"):
            continue
        else:
            sitelist.append(TestSite(line))

    (options, arguments) = getopt.getopt(sys.argv[1:], "dft")
    for (switch, value) in options:
        if switch == "-d":
            # Prettprint the sitelist
            map(lambda x: sys.stdout.write(x.prettyprint() + "%%\n"), sitelist)
            sys.exit(0)
        elif switch == "-f":
            # Dump the sitelist as a .fetchmailrc file
            map(lambda x: sys.stdout.write(x.entryprint()), sitelist)
            sys.exit(0)
        elif switch == "-t":
            # Dump the sitelist in HTML table form
            map(lambda x: sys.stdout.write(x.tableprint()), sitelist)
            sys.exit(0)
        elif switch == "-g":
            for site in sitelist:
                site.testmail()
            # Send test mail to each site
            sys.stdout.write("Delaying to give the test mail time to land...")
            time.sleep(5)
            sys.stdout.write("here we go:\n")
            # Fall through

    # If no options, run the torture test
    try:
        failures = successes = 0
        for site in sitelist:
            print "Testing %s %s at %s" % (site.proto,site.version,site.host)
            site.fetch()
            if not site.failed():
                failures += 1
            else:
                successes += 1

        # OK, summarize results
        print "\n%d successes and %d failures out of %d tests" \
              % (successes, failures, len(sitelist))

        if failures:
            print "Bad status was returned on the following sites:"
            for site in sitelist:
                sys.stdout.write(self.explain)
    except KeyboardInterrupt:
        print "Interrupted."

# end



