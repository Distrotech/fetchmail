cat <<EOF
Description: Remote mail fetch daemon for POP2, POP3, APOP, IMAP
Name: fetchmail
Version: ${1}
Release: ${2}
Source: locke.ccil.org:/pub/esr/fetchmail/fetchmail-${1}.tar.gz
Copyright: freely redistributable
Group: Mail

%prep
%setup

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

%install
make install

%files
%doc README NEWS NOTES fetchmail.FAQ.html FAQ COPYING INSTALL sample.rcfile

%ifarch i386
%endif

/usr/bin/fetchmail
/usr/man/man1/fetchmail.1
EOF
