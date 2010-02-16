These files are here to show how the conversion from SVN to Git was made.
  It is for future reference in case the conversion needs to be re-done to 
fix errors that surface only later.
  It can also be used to showcase a way to convert existing SVN repositories
in traditional trunk/ branches/ tags/ layout.

Not recorded in the script is an effort to force rebasing BRANCH_MAPI on
RELEASE_6-3-8 in order to provide proper ancestry for the MAPI branch, and ease
later merging, and also missing in the script are branch renames and two more
branch-to-tag conversions.
