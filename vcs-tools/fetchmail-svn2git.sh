#!/bin/sh

# fetchmail-svn2git.sh - (C) 2009, 2010 by Matthias Andree, GNU GPL v3.

set -eu

#######################################################################
# Adjust the next three settings below:

# safe can be obtained from <git://repo.or.cz/svn-all-fast-export.git>
# and must be built before we can use it:
safe="$HOME/VCS-other/svn-all-fast-export/svn-all-fast-export"

# svn is the path to a verbatim copy of the server-side SVN repository
# obtained with rsync or with svnadmin dump and load:
svn="$HOME/VCS-mine/fetchmail.svnrepo.backup"

# git specifies where you want the converted repository to end up.
git="$HOME/fetchmail.git"

#
#######################################################################

# There should be no need to change anything below:

#######################################################################

# obtain current directory
dir="$(dirname $0)"

# obtain absolute directory
dir="$( ( cd "$dir" && pwd ) )"

# Pluck these from the same directory as this script
auth="$dir/fetchmail.authors"
rule="$dir/fetchmail.rules"

# create git repository
mkdir "$git"
cd "$git"
git init

# run svn-all-fast-export, which already imports stuff into git
"$safe" --identity-map="$auth" "$rule" "$svn"

# turn tags/ branches into tags
git branch -a \
| grep _tag_ \
| while read a ; do
	if git show-ref -q "$a" ; then
		(
		eval $(git log -1 --format="tformat:GIT_AUTHOR_NAME=\"%an\"%nGIT_AUTHOR_EMAIL=\"%ae\"%nGIT_AUTHOR_DATE=\"%ai\"%nGIT_COMMITTER_NAME=\"%cn\"%nGIT_COMMITTER_EMAIL=\"%ce\"%nGIT_COMMITTER_DATE=\"%ci\"" "$a")
		MSG=$(git log -1 --pretty="tformat:%s%n%n%b" "$a")
		export GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_AUTHOR_DATE
		export GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_COMMITTER_DATE
		if test "$GIT_AUTHOR_NAME" = nobody ; then
			# cvs2svn tag => lightweight
			git tag "${a##_tag_}" "$a"
		else
			# keep message
			git tag -a -m "$MSG" "${a##_tag_}" "$a"
		fi
		git branch -D "$a"
		)
	fi
done

# clean up
git gc --aggressive
