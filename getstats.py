#!/usr/bin/python
#
# Collect statistics on current release.

import commands, string, ftplib

# Get version and date
date = commands.getoutput("date")
ln = commands.getoutput("co -p RCS/*.[chly],v 2>/dev/null | wc -l")
vers = commands.getoutput("sed -n -e '/VERSION/s/VERSION *= *\\(.*\\)/\\1/p' <Makefile")
print "fetchmail-" + vers + " (" + date + "), " + string.strip(ln) + " lines:"

# Get mailing-list statistics.
def bumpcount(str):
    global linecount
    linecount = linecount + 1
ftp = ftplib.FTP('locke.ccil.org', 'esr', 'Malvern')
linecount = 0
ftp.retrlines("RETR fetchmail-friends", bumpcount)
friends = linecount - 1
linecount = 0
ftp.retrlines("RETR fetchmail-announce", bumpcount)
announce = linecount
print "There are %d people on fetchmail-friends and %d on fetchmail-announce."% (friends, announce)

# getstats.py
