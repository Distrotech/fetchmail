cat <<EOF
Description: Remote mail fetcher for POP2, POP3, APOP, IMAP
Name: fetchmail
Version: ${1}
Release: 1
Source: locke.ccil.org:/pub/esr/fetchmail-${1}.tar.gz
Copyright: distributable
Group: Mail

%prep
%setup

%build
%ifarch i386
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr 
%endif

%ifarch axp
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr 
%endif

make

%install
make install


%ifarch i386
%endif

%ifarch i386
%post
%endif


%files
%doc README NEWS RFC NOTES COPYING

%ifarch i386
%endif

/usr/bin/fetchmail
/usr/man/man1/fetchmail.1
EOF
