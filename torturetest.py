#!/usr/bin/env python2

import sys, getopt, os, smtplib, commands, time, gtk, gtk.glade

class TestSite:
    temp = "/usr/tmp/torturestest-%d" % os.getpid()

    def __init__(self, line):
        "Initialize site data from the external representation."
        (self.host, self.mailaddr, self.username, self.password, \
                self.protocol, self.options, self.capabilities, self.recognition, self.comment) = \
                line.strip().split(":")
        if not self.mailaddr:
            self.mailaddr = self.username
        # Test results
        self.status = None
        self.output = None

    def allattrs(self):
        "Return a tuple consisting of alll this site's attributes."
        return (self.host, self.mailaddr, self.username, self.password, \
                self.protocol, self.options, self.capabilities, \
                self.recognition, self.comment)

    def __repr__(self):
        "Return the external representation of this site's data."
        return ":".join(self.allattrs())

    def prettyprint(self):
        "Prettyprint a site entry in human-readable form."
        return "Host: %s\n" \
              "Mail To: %s\n" \
              "Username: %s\n" \
              "Password: %s\n" \
              "Protocol: %s\n" \
              "Options: %s\n" \
              "Capabilities: %s\n" \
              "Recognition: %s\n" \
              "Comment: %s\n" \
              % self.allattrs()

    def entryprint(self):
        "Print a .fetchmailrc entry corresponding to a site entry."
        return "poll %s-%s via %s with proto %s %s\n" \
               "   user %s there with password '%s' is esr here\n\n" \
               % (self.host,self.protocol,self.host,self.protocol,self.options,self.username,self.password)

    def tableprint(self):
        "Print an HTML server-type table entry."
        return "<tr><td>%s: %s</td><td>%s</td>\n" \
               % (self.protocol, self.comment, self.capabilities)

    def id(self):
        "Identify this site."
        rep = "%s %s at %s" % (self.protocol, self.recognition, self.host)
        if self.capabilities:
            rep += " (" + self.capabilities + ")"
        if self.options:
            rep += " using " + self.options
        return rep

    def testmail(self, n=None):
        "Send test mail to the site."
        server = smtplib.SMTP("localhost")
        fromaddr = "esr@thyrsus.com"
        if self.mailaddr.find("@") > -1:
            toaddr = self.mailaddr
        else:
            toaddr = "%s@%s" % (self.mailaddr, self.host)
        msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, toaddr))
        if n != None:
            msg += `n` + ": "
        msg += "Test mail collected from %s.\n" % (self.id(),)
        server.sendmail(fromaddr, toaddr, msg)
        server.quit()

    def fetch(self):
        "Run a mail fetch on this site."
        try:
            ofp = open(TestSite.temp, "w")
            ofp.write('defaults mda "(echo; echo \'From torturetest\' `date`; cat) >>TEST.LOG"\n')
            ofp.write(self.entryprint())
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

class TortureGUI:
    "Torturetest editing GUI,"

    # All site parameters except protocol
    field_map = ('host', 'mailaddr', 'username', 'password', \
                'options', 'capabilities', 'recognition', 'comment')

    def __init__(self):
        # Build the widget tree from the glade XML file.
        self.wtree = gtk.glade.XML("torturetest.glade")
        # File in initial values
        self.combo = self.wtree.get_widget("combo1")
        self.combo.set_popdown_strings(map(lambda x: x.comment, sitelist))
        self.site = sitelist[0]
        self.display(self.site)

        # Provide handlers for the widget tree's events
	mydict = {}
	for key in ('on_torturetest_destroy',
                    'on_quitbutton_clicked',
                    'on_newbutton_clicked',
                    'on_testbutton_clicked',
                    'on_combo_entry1_activate'):
	    mydict[key] = getattr(self, key)
	self.wtree.signal_autoconnect(mydict)

        gtk.mainloop()
        print `self.site`

    def get_widget(self, widget):
        "Get the value of a widget's contents."
        if type(widget) == type(""):
            widget = self.wtree.get_widget(widget)
        if type(widget) == gtk.Entry:
            return widget.get_text()
        elif type(widget) == gtk.SpinButton:
            return widget.get_value()
        elif type(widget) == gtk.TextView:
            return widget.get_buffer().get_text()

    def set_widget(self, name, exp):
        "Set the value of a widget by name."
        widget = self.wtree.get_widget(name)
        if type(widget) == gtk.Entry:
            widget.set_text(exp)
        elif type(widget) == gtk.SpinButton:
            widget.set_value(exp)
        elif type(widget) == gtk.TextView:
            if not widget.get_buffer():
                widget.set_buffer(gtk.TextBuffer())
            widget.get_buffer().set_text(exp)

    def display(self, site):
        for member in TortureGUI.field_map:
            self.set_widget(member + "_entry", getattr(site, member))
        for proto in ('POP3', 'APOP', 'IMAP'):
            self.wtree.get_widget(proto + "_radiobutton").set_active(site.protocol == proto)

    # Housekeeping
    def on_torturetest_destroy(self, obj):
        gtk.mainquit()
    def on_quitbutton_clicked(self, obj):
        gtk.mainquit()
    def on_newbutton_clicked(self, obj):
        print "New"

    def on_combo_entry1_activate(self, obj):
        key = self.combo.entry.get_text()
        for site in sitelist:
            if site.comment.find(key) > -1:
                self.site = site
                self.display(self.site)
                break
    def on_testbutton_clicked(self, obj):
        self.site.fetch()
        print site.output

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

    (options, arguments) = getopt.getopt(sys.argv[1:], "dfp:tigvse")
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
            i = 1
            for site in sitelist:
                print "Sending test mail to " + site.id()
                site.testmail(i)
                i+= 1
            # Send test mail to each site
            sys.stdout.write("Delaying to give the test mail time to land...")
            time.sleep(5)
            sys.stdout.write("here we go:\n")
            # Fall through
        elif switch == "-v":
            # Display the test output
            verbose = 1
        elif switch == "-s":
            # Dump recognition strings of all tested servers as a Python tuple
            print "(" + ",\n".join(map(lambda x: repr(x.recognition), filter(lambda x: x.recognition, sitelist))) + ")"
            sys.exit(0)
        elif switch == "-e":
            TortureGUI()
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
