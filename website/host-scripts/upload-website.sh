#! /bin/sh

# Script to upload fetchmail website from Git repository
# (C) 2008 - 2010 by Matthias Andree. GNU GPL v3.

: ${BERLIOS_LOGIN=m-a}
: ${SOURCEFORGE_LOGIN=m-a}

# abort on error
set -eu

# cd to parent of script
cd "$(dirname "$0")"
cd ..

echo "==>  Running sanity checks"
# make sure we have no dangling symlinks
if LC_ALL=C file * | egrep broken\|dangling ; then
    echo "broken symlinks -> abort" >&2
    exit 1
fi

pids=

echo "==>  Uploading website (rsync) to BerliOS"
# upload
rsync \
    --chmod=ug=rwX,o=rX,Dg=s --perms \
    --copy-links --times --checksum --verbose \
    --exclude host-scripts \
    --exclude .git --exclude '*~' --exclude '#*#' \
    * \
    "$BERLIOS_LOGIN@shell.berlios.de:/home/groups/fetchmail/htdocs/" &
pids="$pids $!"

echo "==>  Uploading website (rsync) to SourceForge"
# upload
rsync \
    --chmod=ug=rwX,o=rX,Dg=s --perms \
    --copy-links --times --checksum --verbose \
    --exclude host-scripts \
    --exclude .git --exclude '*~' --exclude '#*#' \
    * \
    "${SOURCEFORGE_LOGIN},fetchmail@web.sourceforge.net:htdocs/" &
pids="$pids $!"

echo "==>  Uploading website (rsync) to local"
rsync \
    --chmod=ug=rwX,o=rX,Dg=s --perms \
    --copy-links --times --checksum --verbose \
    --exclude host-scripts \
    --exclude .git --exclude '*~' --exclude '#*#' \
    * \
    $HOME/public_html/fetchmail/info/ &
pids="$pids $!"

wait $pids

echo "==>  Synchronizing web dir."
synchome.sh

echo "==>  Done; check rsync output above for success."
