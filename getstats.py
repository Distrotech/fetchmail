#!/usr/bin/python
#
# Collect statistics on current release.

import commands, string, ftplib

# Get version and date
date = commands.getoutput("date")
ln = commands.getoutput("co -p RCS/*.[chly],v 2>/dev/null | wc -l")
vers = commands.getoutput("sed -n -e '/VERSION/s/VERSION *= *\\(.*\\)/\\1/p' <Makefile")
print "fetchmail-" + vers + " (" + date + "), " + string.strip(ln) + " lines:"

# Use local listsize command to grab list statistics
friends = commands.getoutput("listsize friends").strip()
announce = commands.getoutput("listsize announce").strip()
print "There are %s people on fetchmail-friends and %s on fetchmail-announce."% (friends, announce)

# getstats.py
