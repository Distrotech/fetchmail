# Makefile for fetchmail

SUBDIRS=		intl m4 m4-local po

AM_CFLAGS=		@CEFLAGS@
AM_CPPFLAGS=		@CPFLAGS@ -I$(top_srcdir)/intl
AM_LDFLAGS=		@LDEFLAGS@
ACLOCAL_AMFLAGS=	-I m4 -I m4-local
AM_YFLAGS=		-d
BUILT_SOURCES=		rcfile_y.h

bin_PROGRAMS=		fetchmail
dist_bin_SCRIPTS=	fetchmailconf
dist_noinst_SCRIPTS=	html2txt.sh specgen.sh
dist_man1_MANS=		fetchmail.man

# for gettext (used by fetchmail.c, NOT by GNU gettext)
localedir=		$(datadir)/locale
DEFS=			@DEFS@ -DLOCALEDIR=\"$(localedir)\"

noinst_LIBRARIES=	libfm.a
libfm_a_SOURCES=	xmalloc.c base64.c rfc822.c report.c
libfm_a_LIBADD=		$(EXTRAOBJ)
libfm_a_DEPENDENCIES=	$(EXTRAOBJ)
LDADD	=		libfm.a @LIBINTL@ $(LIBOBJS)
DEPENDENCIES=		libfm.a $(LIBOBJS)

fetchmail_SOURCES=	fetchmail.h getopt.h \
		i18n.h kerberos.h md5.h mx.h netrc.h ntlm.h \
		smbbyteorder.h smbdes.h smbmd4.h smbencrypt.h smtp.h \
		socket.h tunable.h \
		socket.c getpass.c pop2.c pop3.c imap.c etrn.c \
		odmr.c fetchmail.c env.c idle.c options.c daemon.c \
		driver.c transact.c sink.c smtp.c \
		uid.c mxget.c md5ify.c cram.c kerberos.c gssapi.c \
		opie.c rpa.c interface.c netrc.c \
		unmime.c conf.c checkalias.c smbdes.c smbencrypt.c \
		smbmd4.c smbutil.c ipv6-connect.c lock.c \
		rcfile_l.l rcfile_y.y

check_PROGRAMS=	rfc822 unmime netrc

rfc822_SOURCES=	rfc822.c
rfc822_CFLAGS=	-DMAIN

unmime_SOURCES=	unmime.c
unmime_CFLAGS=	-DSTANDALONE -DHAVE_CONFIG_H -I$(builddir)

netrc_SOURCES=	netrc.c xmalloc.c report.c
netrc_CFLAGS=	-DSTANDALONE -DHAVE_CONFIG_H -I$(builddir)

# For some losing Unix makes.
SHELL = /bin/sh
@SET_MAKE@

fetchmail.spec: Makefile.in specgen.sh
	$(srcdir)/specgen.sh $(VERSION) >fetchmail.spec

DISTDOCS=	FAQ FEATURES NOTES fetchmail-man.html fetchmail-FAQ.html \
		design-notes.html todo.html fetchmail-features.html \
		README.SSL README.NTLM

# extra directories to ship
distdirs = rh-config contrib beos

EXTRA_DIST= $(DISTDOCS) fetchmail.spec $(distdirs)

FAQ: fetchmail-FAQ.html
	AWK=$(AWK) $(SHELL) $(srcdir)/html2txt.sh $(srcdir)/fetchmail-FAQ.html >$@ || { rm -f $@ ; exit 1 ; }

FEATURES: fetchmail-features.html
	AWK=$(AWK) $(SHELL) $(srcdir)/html2txt.sh $(srcdir)/fetchmail-features.html >$@ || { rm -f $@ ; exit 1 ; }

NOTES: design-notes.html
	AWK=$(AWK) $(SHELL) $(srcdir)/html2txt.sh $(srcdir)/design-notes.html >$@ || { rm -f $@ ; exit 1 ; }

TODO: todo.html
	AWK=$(AWK) $(SHELL) $(srcdir)/html2txt.sh $(srcdir)/todo.html >$@ || { rm -f $@ ; exit 1 ; }

# man2html no longer chokes and dies on this man page,
# but manServer.pl does a much better job. 
fetchmail-man.html: fetchmail.man
	env - PATH=$$PATH $(srcdir)/dist-tools/manServer.pl fetchmail.man >$@ \
	|| { rm -f $@ ; exit 1 ; }

dist-hook:
	cd $(distdir) && find $(distdirs) intl po -name .svn -type d -prune -exec rm -rf '{}' ';'
	cd $(distdir) && find $(distdirs) intl po -name '*~' -exec rm -f '{}' ';'

# The following sets edit modes for GNU EMACS.
# Local Variables:
# compile-command:"configure"
# End:
