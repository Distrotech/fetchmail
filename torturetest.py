#!/usr/bin/env python

import sys, getopt, os, smtplib

class TestSite:
    def __init__(self, line):
        (self.host, self.userid, self.password, \
                self.proto, self.options, self.version, self.comment) = \
                line.strip().split(":")

    def allattrs(self):
        return (self.host, self.userid, self.password, \
                         self.proto, self.options, self.version, self.comment)

    def __repr__(self):
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
            # Send test mail to each site
            server = smtplib.SMTP("localhost")
            fromaddr = "esr@thyrsus.com"
            for site in sitelist:
                toaddr = "%s@%s" % (site.userid, site.host)
                msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, toaddr))
                msg += "Test mail collected from %s.\n" % (toaddr,)
                server.sendmail(fromaddr, toaddr, msg)
            server.quit()
            sys.stdout.write("Delaying to give the test mail time to land...")
            time.sleep(5)
            sys.stdout.write("here we go:\n")
            # Fall through

    # If no options, run the torture test
    try:
        failures = successes = 0
        returns = []
        for site in sitelist:
            print "#\n#Testing %s %s at %s\n#" \
                  % (site.proto,site.version,site.host)

            # Generate the control file for this run
            temp = "/usr/tmp/torturestest-%d" % os.getpid()
            ofp = open(temp, "w")
            ofp.write(site.entryprint())
            ofp.close()

            # Run the test
            status = os.system("fetchmail -d0 -v -f - <%s" % temp)
            print "Status: %d" % status
            returns.append((site, status))
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) > 1:
                failures += 1
            else:
                successes += 1
    finally:
        os.remove(temp)

    # OK, summarize results
    print "\n%d successes and %d failures out of %d tests" \
          % (successes, failures, len(sitelist))

    if failures:
        print "Bad status was returned on the following sites:"
        for (site, status) in returns:
            if not os.WIFEXITED(status):
                sys.stdout.write("%s %s at %s: " \
                             % (site.proto,site.version,site.host))
                sys.stdout.write("abnormal termination\n")
            elif os.WEXITSTATUS(status) > 1:
                sys.stdout.write("%s %s at %s: " \
                             % (site.proto,site.version,site.host))
                sys.stdout.write("%d\n" % os.WEXITSTATUS(status))
# end



