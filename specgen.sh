cat <<EOF
Description: Remote mail fetch daemon for POP2, POP3, APOP, IMAP
Name: fetchmail
Version: ${1}
Release: 1
Vendor: Eric Conspiracy Secret Labs
Source: locke.ccil.org:/pub/esr/fetchmail/fetchmail-${1}.tar.gz
URL: http://www.ccil.org/~esr/fetchmail
Group: Applications/Mail
Copyright: GPL
Icon: fetchmail.gif
Requires: smtpdaemon

%prep
%setup

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

%install
make install

%files
%doc README NEWS NOTES fetchmail-FAQ.html FAQ COPYING INSTALL sample.rcfile

%ifarch i386
%endif

/usr/bin/fetchmail
/usr/man/man1/fetchmail.1
EOF
