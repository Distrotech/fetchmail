# Makefile for fetchmail

SUBDIRS=		. po
AUTOMAKE_OPTIONS=	1.11 foreign no-dist-gzip dist-xz

AM_CPPFLAGS=		-I$(srcdir)/libesmtp
ACLOCAL_AMFLAGS=	-I m4 -I m4-local
AM_YFLAGS=		-d
BUILT_SOURCES=		rcfile_y.h

bin_PROGRAMS=		fetchmail

dist_noinst_SCRIPTS=	specgen.sh
dist_man1_MANS=		fetchmail.man

pys=			fetchmailconf.py
pym=			fetchmailconf.man

if HAVE_LIBPWMD
CFLAGS += @libpwmd_CFLAGS@
LDFLAGS += @libpwmd_LIBS@
endif

if HAVE_PYTHON
nodist_bin_SCRIPTS=	fetchmailconf
python_PYTHON=		$(pys)
dist_man1_MANS+=	$(pym)
EXTRA_DIST=
else
noinst_PYTHON=		$(pys)
EXTRA_DIST=		$(pym)
endif

CLEANFILES=		$(nodist_bin_SCRIPTS)

# for gettext (used by fetchmail.c, NOT by GNU gettext)
localedir=		$(datadir)/locale
DEFS=			@DEFS@ -DLOCALEDIR=\"$(localedir)\"

noinst_LIBRARIES=	libfm.a
libfm_a_SOURCES=	xmalloc.c base64.c rfc822.c report.c rfc2047e.c \
			servport.c ntlm.h smbbyteorder.h smbdes.h smbmd4.h \
			smbencrypt.h smbdes.c smbencrypt.c smbmd4.c smbutil.c \
			libesmtp/gethostbyname.h libesmtp/gethostbyname.c \
			smbtypes.h fm_getaddrinfo.c tls.c rfc822valid.c \
			xmalloc.h sdump.h sdump.c x509_name_match.c \
			fm_strl.h md5c.c daemon.c testmode.c unmime.c \
			netrc.h netrc.c
if NTLM_ENABLE
libfm_a_SOURCES += ntlmsubr.c
endif
libfm_a_LIBADD=		$(EXTRAOBJ)
libfm_a_DEPENDENCIES=	$(EXTRAOBJ)
LDADD	=		libfm.a @LIBINTL@ $(LIBOBJS)
DEPENDENCIES=		libfm.a $(LIBOBJS)

check_PROGRAMS=		t_x509_name_match

TESTS=			t.smoke t.validate-xhtml t.x509_name_match
TESTS_ENVIRONMENT=	srcdir="$(srcdir)" LC_ALL=C TZ=UTC SHELL="$(SHELL)" $(SHELL)

fetchmail_SOURCES=	fetchmail.h getopt.h \
		gettext.h kerberos.h fm_md5.h smtp.h \
		socket.h tunable.h \
		socket.c getpass.c \
		fetchmail.c env.c idle.c options.c \
		driver.c transact.c sink.c smtp.c \
		idlist.c uid.c md5ify.c cram.c gssapi.c \
		opie.c interface.c \
		conf.c checkalias.c uid_db.h uid_db.c\
		lock.h lock.c \
		rcfile_l.l rcfile_y.y \
		ucs/norm_charmap.c ucs/norm_charmap.h
if POP3_ENABLE
fetchmail_SOURCES += pop3.c
endif
if IMAP_ENABLE
fetchmail_SOURCES +=	imap.cpp IMAPCapa.h IMAPCapa.cpp
check_PROGRAMS +=	IMAPCapa
IMAPCapa_SOURCES =	t_IMAPCapa.cpp IMAPCapa.cpp
TESTS +=		t.IMAPCapa
endif
if ETRN_ENABLE
fetchmail_SOURCES += etrn.c
endif
if ODMR_ENABLE
fetchmail_SOURCES += odmr.c
endif
if RPA_ENABLE
fetchmail_SOURCES += rpa.c
endif
if NEED_GETNAMEINFO
fetchmail_SOURCES += KAME/getnameinfo.c
endif
if NEED_GETADDRINFO
fetchmail_SOURCES += libesmtp/getaddrinfo.h libesmtp/getaddrinfo.c
endif

check_PROGRAMS +=	t_rfc822 t_unmime t_netrc t_rfc2047e t_rfc822valid \
			t_idle

t_rfc2047e_SOURCES=	t_rfc2047e.cpp

t_rfc822_SOURCES=	t_rfc822.cpp

t_idle_SOURCES=		t_idle.cpp idle.c

t_x509_name_match_SOURCES=	t_x509_name_match.cpp

t_unmime_SOURCES=	t_unmime.cpp

t_netrc_SOURCES=	t_netrc.cpp xmalloc.c report.c

@SET_MAKE@

fetchmail.spec: Makefile.in specgen.sh
	$(srcdir)/specgen.sh $(VERSION) >fetchmail.spec

DISTDOCS=	FAQ FEATURES NOTES OLDNEWS fetchmail-man.html \
		design-notes.html esrs-design-notes.html todo.html \
		fetchmail-features.html README.SSL README.NTLM \
		README.packaging README.SSL-SERVER \
		fetchmail-FAQ.book fetchmail-FAQ.pdf fetchmail-FAQ.html \
		Mailbox-Names-UTF7.txt Mailbox-Names-UTF7.html \
		fetchmail-EN-2010-03.txt \
		fetchmail-SA-2010-02.txt \
		fetchmail-SA-2010-01.txt \
		fetchmail-SA-2009-01.txt \
		fetchmail-SA-2008-01.txt \
		fetchmail-SA-2007-02.txt \
		fetchmail-SA-2007-01.txt \
		fetchmail-SA-2006-03.txt \
		fetchmail-SA-2006-02.txt \
		fetchmail-SA-2006-01.txt \
		fetchmail-SA-2005-01.txt \
		fetchmail-SA-2005-02.txt \
		fetchmail-SA-2005-03.txt

# extra directories to ship
distdirs = rh-config contrib beos

EXTRA_DIST+=	$(DISTDOCS) $(distdirs) \
		fetchmail.spec fetchmail.xpm \
		strlcpy.3 bighand.png \
		m4/codeset.m4 \
		m4/gettext.m4 \
		m4/glibc2.m4 \
		m4/glibc21.m4 \
		m4/iconv.m4 \
		m4/intdiv0.m4 \
		m4/intl.m4 \
		m4/intldir.m4 \
		m4/intlmacosx.m4 \
		m4/intmax.m4 \
		m4/inttypes-pri.m4 \
		m4/inttypes_h.m4 \
		m4/lcmessage.m4 \
		m4/lib-ld.m4 \
		m4/lib-link.m4 \
		m4/lib-prefix.m4 \
		m4/lock.m4 \
		m4/longlong.m4 \
		m4/nls.m4 \
		m4/po.m4 \
		m4/printf-posix.m4 \
		m4/progtest.m4 \
		m4/size_max.m4 \
		m4/stdint_h.m4 \
		m4/uintmax_t.m4 \
		m4/visibility.m4 \
		m4/wchar_t.m4 \
		m4/wint_t.m4 \
		m4/xsize.m4 \
		m4-local/ac-archive-license.txt \
		m4-local/ac_ma_search_package.m4 \
		$(TESTS) t.rc t.regression \
		dist-tools/html2txt \
		dist-tools/manServer.pl \
		Doxyfile

fetchmailconf:
	( echo '#! /bin/sh' && echo 'exec @PYTHON@ @pythondir@/fetchmailconf.py "$$@"' ) >$@ && chmod +x $@ || { rm -f $@ ; exit 1; }

FAQ: fetchmail-FAQ.html $(srcdir)/dist-tools/html2txt
	AWK=$(AWK) $(SHELL) $(srcdir)/dist-tools/html2txt $(srcdir)/fetchmail-FAQ.html >$@ || { rm -f $@ ; exit 1 ; }

fetchmail-FAQ.pdf: fetchmail-FAQ.html fetchmail-FAQ.book bighand.png
	$(AWK) '/^[ \t]*<h1/ {sec++; } {if (sec < 2 || sec > 3) print $0;}' <$(srcdir)/fetchmail-FAQ.html >fetchmail-FAQ-print.html
	htmldoc --logoimage $(srcdir)/bighand.png --batch $(srcdir)/fetchmail-FAQ.book || { rm -f $@ ; exit 1 ; }
	rm -f fetchmail-FAQ-print.html

FEATURES: fetchmail-features.html $(srcdir)/dist-tools/html2txt
	AWK=$(AWK) $(SHELL) $(srcdir)/dist-tools/html2txt $(srcdir)/fetchmail-features.html >$@ || { rm -f $@ ; exit 1 ; }

NOTES: design-notes.html esrs-design-notes.html $(srcdir)/dist-tools/html2txt
	   echo "This file contains two articles reformatted from HTML." > $@ \
	&& echo "------------------------------------------------------" >> $@ \
	&& echo "" >> $@ \
	&& AWK=$(AWK) $(SHELL) $(srcdir)/dist-tools/html2txt $(srcdir)/design-notes.html >>$@ \
	&& AWK=$(AWK) $(SHELL) $(srcdir)/dist-tools/html2txt $(srcdir)/esrs-design-notes.html >>$@ \
	|| { rm -f $@ ; exit 1 ; }

TODO: todo.html $(srcdir)/dist-tools/html2txt
	AWK=$(AWK) $(SHELL) $(srcdir)/dist-tools/html2txt $(srcdir)/todo.html >$@ || { rm -f $@ ; exit 1 ; }

fetchmail-man.html: fetchmail.man $(srcdir)/dist-tools/manServer.pl
	env - "PATH=$$PATH" $(srcdir)/dist-tools/manServer.pl $(srcdir)/fetchmail.man >$@ \
	|| { rm -f $@ ; exit 1 ; }

dist-hook:
	cd $(distdir) && find $(distdirs) po -name .git -type d -prune -exec rm -rf '{}' ';'
	cd $(distdir) && find $(distdirs) po -name '*~' -exec rm -f '{}' ';'

.PHONY: lsm
lsm: genlsm.sh dist
	$(SHELL) genlsm.sh >$(PACKAGE)-$(VERSION).lsm

# this target expects a .rsyncs file with lines of this format:
# host:directory/
# it will call rsync from its source directory to the destination for
# each of them, running them in parallel
rsync:  distdir $(srcdir)/.rsyncs
	@( cat $(srcdir)/.rsyncs | sed -e 's}^}rsync -aH --delete-after $(PACKAGE)-$(VERSION)/ }; s/\($$\)/ \&/;' ; echo "wait" ) | $(SHELL) -x

.PHONY: import-translations
import-translations:
	rsync -Lrtvz translationproject.org::tp/latest/fetchmail/  $(top_srcdir)/po
	cd $(top_builddir)/po && $(MAKE) update-po

SUFFIXES = .html .txt
.txt.html:
	asciidoc --unsafe -a toc -a data-uri -o $@ $< || { rm -f $@ ; exit 1 ; }

# The following sets edit modes for GNU EMACS.
# Local Variables:
# compile-command:"configure"
# End:
