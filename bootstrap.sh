#! /bin/sh

# bootstrap.sh - bootstrap the fetchmail build after a fresh subversion checkout
# (C) 2004  Matthias Andree -- GNU GPL V2

set -e
# sanity checks:
test -f fetchmail.h
test -f fetchmail.c
test -f Makefile.am
rm -rf autom4te.cache
echo
echo "Please stand by while generating files with autoreconf, this may"
echo "take a minute or two..."
echo
autoreconf -isv
echo
echo "You can now run ./configure and make as usual. See INSTALL for details."
echo
