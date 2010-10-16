test "$SEND_ANNOUNCEMENTS" = doit || { echo "read the source, luke! -> $0" ; cat "$0" ; exit 1 ; }

ANN=fetchmail-EN-2010-03
FILE=$HOME/VCS-mine/fetchmail.git/$ANN.txt
test -r $FILE || { echo "Cannot find $FILE." ; exit 1 ; }
SUBJECT="fetchmail erratum notice $ANN"
MAILER=mail

$MAILER -r matthias.andree@gmx.de -s "$SUBJECT" <$FILE \
    vendor-sec@lst.de \
    fetchmail-announce@lists.berlios.de
