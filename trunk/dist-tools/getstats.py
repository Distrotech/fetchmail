#!/usr/bin/env python
#
# Collect statistics on current release.

import commands, os, string, ftplib

# Get version and date
date = commands.getoutput("LC_TIME=C date -u")
pid = os.getpid()
# this is a fast variant using the base of the current working directory
# (ignores uncommitted modifications)
if os.system("svn export -q -rBASE . /tmp/getstats.%d" % pid):
    print "SVN FAILED"
    os.exit(1)
# this is a slower variant that may export the whole tree across the net
#os.system("svn export -rCOMMITTED . /tmp/getstats.%d" % pid)
ln = commands.getoutput("cat /tmp/getstats.%d/*.[chly] 2>/dev/null | wc -l" % pid)
os.system("rm -rf /tmp/getstats.%d" % pid)
vers = commands.getoutput("sed -n -e '/AC_INIT/s/AC_INIT(\[.*\],\[\\(.*\\)\])/\\1/p' <configure.ac")
print "fetchmail-" + vers + " (" + date + "), " + string.strip(ln) + " lines:"

# Use local listsize command to grab list statistics
#friends = commands.getoutput("listsize friends").strip()
#announce = commands.getoutput("listsize announce").strip()
#print "There are %s people on fetchmail-friends and %s on fetchmail-announce."% (friends, announce)

# getstats.py
