cat <<EOF
Name:		fetchmail
Version:	${1}
Release:	1
Vendor:		Eric Conspiracy Secret Labs
Source:		locke.ccil.org:/pub/esr/fetchmail/fetchmail-${1}.tar.gz
URL:		http://earthspace.net/~esr/fetchmail
Group:		Applications/Mail
Copyright:	GPL
Icon:		fetchmail.gif
Requires:	smtpdaemon
BuildRoot:      /tmp/fetchmail-%{version}-root

%description
fetchmail is a free, full-featured, robust, and well-documented remote
mail retrieval and forwarding utility intended to be used over
on-demand TCP/IP links (such as SLIP or PPP connections).  It
retrieves mail from remote mail servers and forwards it to your local
(client) machine's delivery system, so it can then be be read by
normal mail user agents such as mutt, elm, pine, or mailx.

%prep
%setup

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/{bin,man/man1}
make prefix=$RPM_BUILD_ROOT/usr install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(-,root,root) %doc README NEWS NOTES fetchmail-FAQ.html FAQ COPYING INSTALL
sample.rcfile
%attr(-,root,root) /usr/bin/fetchmail
%attr(-,root,root) /usr/man/man1/fetchmail.1
EOF
