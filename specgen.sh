cat <<EOF
%define name fetchmail
%define version ${1}
%define release 1
%define builddir \$RPM_BUILD_DIR/%{name}-%{version}
Name:		%{name}
Version:	%{version}
Release:	%{release}
Vendor:		Eric Conspiracy Secret Labs
Packager:	Eric S. Raymond <esr@thyrsus.com>
URL:		http://www.tuxedo.org/~esr/fetchmail
Source:         %{name}-%{version}.tar.gz
Group:		Applications/Mail
Group(pt_BR):   Aplicações/Correio Eletrônico
Copyright:	GPL
Icon:		fetchmail.gif
Requires:	smtpdaemon
BuildRoot:	/var/tmp/%{name}-%{version}
Summary:	Full-featured POP/IMAP mail retrieval daemon
Summary(fr):    Collecteur (POP/IMAP) de courrier électronique
Summary(de):    Program zum Abholen von E-Mail via POP/IMAP
Summary(pt_BR): Busca mensagens de um servidor usando POP ou IMAP
Summary(es_AR): Recolector de correo via POP/IMAP

%description
fetchmail is a free, full-featured, robust, and well-documented remote
mail retrieval and forwarding utility intended to be used over
on-demand TCP/IP links (such as SLIP or PPP connections).  It
retrieves mail from remote mail servers and forwards it to your local
(client) machine's delivery system, so it can then be be read by
normal mail user agents such as mutt, elm, pine, (x)emacs/gnus, or mailx.
Comes with an interactive GUI configurator suitable for end-users.

%description -l fr
Fetchmail est un programme qui permet d'aller rechercher du courrier
électronique sur un serveur de mail distant. Fetchmail connait les
protocoles POP (Post Office Protocol), IMAP (Internet Mail Access
Protocol) et délivre le courrier électronique a travers le
serveur SMTP local (habituellement sendmail).

%description -l de
Fetchmail ist ein freies, vollständiges, robustes und
wohldokumentiertes Werkzeug zum Abholen und Weiterreichen von E-Mail,
gedacht zum Gebrauchüber temporäre TCP/IP-Verbindungen (wie
z.B. SLIP- oder PPP-Verbindungen).  Es holt E-Mail von (weit)
entfernten Mail-Servern abund reicht sie an das Auslieferungssystem
der lokalen Client-Maschine weiter, damit sie dann von normalen MUAs
("mail user agents") wie mutt, elm, pine, (x)emacs/gnus oder mailx
gelesen werden kann.  Ein interaktiver GUI-Konfigurator auch gut
geeignet zum Gebrauch durch Endbenutzer wird mitgeliefert.

%description -l pt_BR
fetchmail é um programa que é usado para recuperar mensagens de um
servidor de mail remoto. Ele pode usar Post Office Protocol (POP)
ou IMAP (Internet Mail Access Protocol) para isso, e entrega o mail
através do servidor local SMTP (normalmente sendmail).

%description -l es_AR
fetchmail es una utilidad gratis, completa, robusta y bien documentada
para la recepción y reeenvío de correo pensada para ser usada en co-
nexiones TCP/IP por demanda (como SLIP y PPP). Recibe el correo de
servidores remotos y lo reenvía a el sistema de entrega local, siendo de
ese modo posible leerlo con programas como mutt, elm, pine, (x)emacs/gnus
o mailx. Contiene un configurador GUI interactivo pensado para usuarios.

%prep
%setup

%build
CFLAGS="\$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

%install
if [ -d \$RPM_BUILD_ROOT ]; then rm -rf \$RPM_BUILD_ROOT; fi
mkdir -p \$RPM_BUILD_ROOT/{etc/X11/wmconfig,usr/lib/rhs/control-panel}
make install prefix=\$RPM_BUILD_ROOT/usr
cp %{builddir}/rh-config/*.{xpm,init} \$RPM_BUILD_ROOT/usr/lib/rhs/control-panel
cp %{builddir}/fetchmail.man \$RPM_BUILD_ROOT/usr/man/man1/fetchmail.1
gzip -9f \$RPM_BUILD_ROOT/usr/man/man1/fetchmail.1
cd \$RPM_BUILD_ROOT/usr/man/man1
ln -sf fetchmail.1.gz fetchmailconf.1.gz
rm -rf %{builddir}/contrib/RCS
chmod 644 %{builddir}/contrib/*
cp %{builddir}/rh-config/fetchmailconf.wmconfig \$RPM_BUILD_ROOT/etc/X11/wmconfig/fetchmailconf

%clean
rm -rf \$RPM_BUILD_ROOT

%files
%defattr (644, root, root, 755)
%doc README NEWS NOTES FAQ COPYING FEATURES sample.rcfile contrib
%doc fetchmail-features.html fetchmail-FAQ.html design-notes.html
/usr/lib/rhs/control-panel/fetchmailconf.xpm
/usr/lib/rhs/control-panel/fetchmailconf.init
/etc/X11/wmconfig/fetchmailconf
%defattr (644, root, man)
/usr/man/man1/*.1.gz
%defattr (755, root, root)
/usr/bin/fetchmail
/usr/bin/fetchmailconf
EOF
