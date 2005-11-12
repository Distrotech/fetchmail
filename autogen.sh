#!/bin/sh
#
# autogen.sh glue for fetchmail
# $Id: autogen.sh,v 1.1 2001/05/12 08:03:50 esr Exp $
#
set -e

# The idea is that we make sure we're always using an up-to-date
# version of all the auto* script chain for the build. The GNU autotools
# are rather badly designed in that area.

autopoint
aclocal -I m4
autoheader
#automake --verbose --foreign --add-missing

#we don't use symlinks because of debian's build system,
#but they would be a better choice.
AM=/usr/share/automake-1.9
for i in config.guess config.sub missing install-sh ; do
	test -r ${AM}/${i} && cp -f ${AM}/${i} .
	chmod 755 ${i}
done

autoconf

#
# For the Debian build, refresh list of +x scripts, to avoid
# possible breakage if upstream tarball does not include the file
# or if it is mispackaged for whatever reason
#

test -d debian && {
	rm -f debian/executable.files
	find -type f -perm +111 ! -name '.*' -fprint debian/executable.files
}

exit 0
