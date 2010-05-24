#!/usr/bin/env python
#
# Collect statistics on current release.

import commands, os, string, ftplib

# Get version and date
date = commands.getoutput("LC_TIME=C date +'%Y-%m-%d'")
pid = os.getpid()
os.mkdir("/tmp/getstats.%d" % pid)

cmd = "git archive --format=tar HEAD | ( cd /tmp/getstats.%d && tar -xf -)" % pid

if os.system(cmd):
    print "git-archive FAILED"
    os.exit(1)

ln = commands.getoutput("cat /tmp/getstats.%d/*.[chly] 2>/dev/null | wc -l" % pid)
os.system("rm -rf /tmp/getstats.%d" % pid)
vers = commands.getoutput("sed -n -e '/AC_INIT/s/AC_INIT(\\[.\\+\\],\\[\\(.*\\)\\],.*)/\\1/p' <configure.ac")
print "fetchmail-" + vers + " (released " + date + ", " + string.strip(ln) + " LoC):"

# end of getstats.py
