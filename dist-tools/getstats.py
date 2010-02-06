#!/usr/bin/env python
#
# Collect statistics on current release.

import commands, os, string, ftplib

print "This script must be adjusted for Git."
exit(1)

# Get version and date
date = commands.getoutput("LC_TIME=C date -u")
pid = os.getpid()
if True:
    # this is a fast variant using the base of the current working directory
    # (ignores uncommitted modifications)
    cmd = "svn export -q -rBASE . /tmp/getstats.%d" % pid
else:
    #  this is a slower variant that may export the whole tree across
    #  the net
    cmd = "svn export -rCOMMITTED . /tmp/getstats.%d" % pid

if os.system(cmd):
    print "SVN FAILED"
    os.exit(1)

ln = commands.getoutput("cat /tmp/getstats.%d/*.[chly] 2>/dev/null | wc -l" % pid)
os.system("rm -rf /tmp/getstats.%d" % pid)
vers = commands.getoutput("sed -n -e '/AC_INIT/s/AC_INIT(\\[.\\+\\],\\[\\(.*\\)\\],.*)/\\1/p' <configure.ac")
print "fetchmail-" + vers + " (" + date + "), " + string.strip(ln) + " lines:"

# end of getstats.py
