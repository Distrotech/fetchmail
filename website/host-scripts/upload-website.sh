#! /bin/sh

# Script to upload fetchmail website from SVN repository
# (C) 2008 - 2009 by Matthias Andree. GNU GPL v3.

: ${BERLIOS_LOGIN=m-a}

# abort on error
set -e

# cd to parent of script
cd $(dirname "$0")
cd ..

echo "==>  Running sanity checks"
# make sure we have no dangling symlinks
if file * | egrep broken\|dangling ; then
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
    --exclude .svn --exclude '*~' --exclude '#*#' \
    * \
    "$BERLIOS_LOGIN@shell.berlios.de:/home/groups/fetchmail/htdocs/" &
pids="$pids $!"

echo "==>  Uploading website (rsync) to local"
rsync \
    --chmod=ug=rwX,o=rX,Dg=s --perms \
    --copy-links --times --checksum --verbose \
    --exclude host-scripts \
    --exclude .svn --exclude '*~' --exclude '#*#' \
    * \
    $HOME/public_html/fetchmail/info/ &
pids="$pids $!"

wait $pids

echo "==>  Synchronizing web dir."
synchome.sh

echo "==>  Done; check rsync output above for success."
