test "$SEND_ANNOUNCEMENTS" = doit || { echo "read the source, luke! -> $0" ; cat "$0" ; exit 1 ; }

ANN=fetchmail-SA-2011-01
FILE=$HOME/VCS-mine/fetchmail.git/$ANN.txt
test -r $FILE || { echo "Cannot find $FILE." ; exit 1 ; }
CVE=$(sed -n '/^CVE Name:/ { s/^.*:[ 	]*//p;q; }' $FILE)
SUBJECT="fetchmail security announcement $ANN ($CVE)"
MAILER=mail

$MAILER -r ma+bt@dt.e-technik.uni-dortmund.de -s "$SUBJECT" <$FILE \
    bugtraq@securityfocus.com

$MAILER -r matthias.andree@gmx.de -s "$SUBJECT" <$FILE \
    fetchmail-announce@lists.berlios.de
