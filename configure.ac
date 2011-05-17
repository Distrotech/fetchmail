dnl Autoconfigure input file for fetchmail
#
# Fetchmail automatic configuration support
#
# Eric S. Raymond <esr@thyrsus.com>
# 2004 - 2010 Matthias Andree <matthias.andree@gmx.de>
#
dnl Process this file with autoconf to produce a configure script.
dnl

dnl XXX - if bumping version here, check fetchmail.man, too!
AC_INIT([fetchmail],[7.0.0-alpha2],[fetchmail-devel@lists.berlios.de])
AC_CONFIG_SRCDIR([fetchmail.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_LIBOBJ_DIR([.])

AC_CANONICAL_HOST

dnl keep this before stuff that runs the compiler!
AC_USE_SYSTEM_EXTENSIONS

dnl automake options are in Makefile.am
AC_PREREQ(2.64)
dnl 2.60 required for AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE

dnl python is optional
#
# you can pass PYTHON=: in environment or on the command line
# to disable python detection and continue without building/installing
# fetchmail.conf -- be sure to check README.packaging, too!
#
AM_PATH_PYTHON(2.0,,AC_MSG_WARN([Disabling fetchmailconf: python 2.0 or greater not found]))
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

AC_PROG_AWK
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LEX
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_YACC

dnl check for b0rked Solaris (and other shells) and find one that works
AC_MSG_CHECKING(for a working shell...)
for i in /usr/xpg6/bin/sh /usr/xpg4/bin/sh /usr/ccs/bin/sh /bin/sh /usr/bin/sh /bin/ksh /bin/bash /usr/local/bin/bash ; do
    $i -c 'if ! false ; then echo $(echo ok) ; fi' >config.$$ 2>/dev/null
    j=`cat config.$$`
    rm -f config.$$
    if test "x$j" = "xok" ; then
        SHELL=$i
        AC_SUBST(SHELL)
        break
    fi
done
AC_MSG_RESULT($SHELL)
if test "x$SHELL" = "x" ; then
    AC_MSG_ERROR(no SUS compliant shell found - on Solaris, install SUNWxcu4)
fi

AC_CHECK_HEADERS([arpa/nameser.h])

AC_CHECK_HEADERS([resolv.h],,,[
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
])

AC_CHECK_DECLS([h_errno],,,[
	AC_INCLUDES_DEFAULT
	#include <netdb.h>
])

# Check for OS special cases
case $host_os in
darwin*)
    AC_MSG_NOTICE(found Darwin - Adding -DBIND_8_COMPAT to CFLAGS)
    CPPFLAGS="$CPPFLAGS -DBIND_8_COMPAT"
    ;;
# Check for FreeBSD special case: more libs needed
freebsd*)
    AC_MSG_NOTICE(found FreeBSD - Adding -lkvm -lcom_err to standard libraries)
    LIBS="$LIBS -lkvm -lcom_err"
    ;;
esac

AC_CACHE_SAVE

dnl i18n
AM_GNU_GETTEXT([external], [need-ngettext])
AM_GNU_GETTEXT_VERSION([0.17])
dnl end i18n

# Under sysV68, socket and friends are provided by the C library.
# -linet does not provide socket, but causes multiple definition
# errors at link-time.  It is thus better to only use the C library.
# So don't add -linet to the link list unless it's necessary
AC_CHECK_FUNC(socket,
    AC_MSG_RESULT(using libc's socket),
    AC_CHECK_LIB(socket,socket)
    AC_CHECK_LIB(inet,socket))

# The condition in this test copes with the presence of inet_addr in libc6.
AC_CHECK_FUNC(inet_addr,
    AC_MSG_RESULT(using libc's inet_addr),
    AC_CHECK_LIB(nsl,inet_addr))

AC_REPLACE_FUNCS([stpcpy strlcpy strlcat])

AC_CHECK_FUNC(getopt_long, [],
              [AC_LIBSOURCES([getopt.c, getopt1.c])
	       EXTRAOBJ="$EXTRAOBJ getopt.\$(OBJEXT) getopt1.\$(OBJEXT)"])

AC_SUBST(EXTRAOBJ)

AC_CHECK_FUNCS(vsyslog inet_aton)

dnl INET6 is used by KAME/getnameinfo
AC_CACHE_CHECK(for AF_INET6/PF_INET6,ac_cv_inet6,
AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM([[
    #include <sys/types.h>
    #include <sys/socket.h>
  ]],[[
    int foo = AF_INET6;
    int bar = PF_INET6;
  ]])],
  ac_cv_inet6=yes , ac_cv_inet6=no
))
if test "x$ac_cv_inet6" = xyes
then
    AC_DEFINE(INET6,1,Define to 1 if your system defines AF_INET6 and PF_INET6.)
fi

# Under Red Hat 4.0 (and many other Linuxes) -lresolv is seriously flaky
# and breaks gethostbyname(2).  It's better to use the bind stuff in the C
# library.  So don't add -lresolv to the link list unless it's necessary
# (It will be necessary when using GNU libc6).
old_LIBS="$LIBS"
for lib in '' -lresolv; do
    if test -z "$lib"; then
       AC_MSG_CHECKING([for res_search in libc])
    else
       AC_MSG_CHECKING([for res_search in $lib])
    fi
    LIBS="$old_LIBS $lib"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif
extern int res_search();
]], [[res_search(0, 0, 0, 0, 0); dn_skipname(0,0);]])],
    [AC_MSG_RESULT([found])
     AC_DEFINE(HAVE_RES_SEARCH, [1],
	       [Define to 1 if you have the 'res_search' and 'dn_skipname' functions.])
     break], [AC_MSG_RESULT([not found])])
     LIBS=$old_LIBS
done

dnl Check for libcrypt -- it may live in libc or libcrypt, as on IRIX
AC_CHECK_FUNC(crypt, , AC_CHECK_LIB(crypt,crypt))

AC_MSG_CHECKING(sys_siglist declaration in signal.h or unistd.h)
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <signal.h>
/* NetBSD declares sys_siglist in <unistd.h>.  */
#include <unistd.h>
]], [[char *msg = *(sys_siglist + 1);]])],[AC_DEFINE(SYS_SIGLIST_DECLARED,1,[Define if 'sys_siglist' is declared by <signal.h>.]) AC_MSG_RESULT(yes)],[AC_MSG_RESULT(no)])

AC_DEFINE_UNQUOTED(PID_DIR, "/var/run", directory for PID lock files)

AC_ARG_ENABLE(pwmd,
	[  --enable-pwmd           enable Password Manager Daemon support],
	, [enable_pwmd=no])

if test "$enable_pwmd" = "yes"; then
    PKG_CHECK_EXISTS([libpwmd], have_libpwmd=1,
		     AC_MSG_ERROR([Could not find libpwmd pkg-config module.]))


    PKG_CHECK_MODULES([libpwmd], [libpwmd >= 6.0.0])
    AM_CONDITIONAL(HAVE_LIBPWMD, true)
    AC_DEFINE(HAVE_LIBPWMD, 1, [Define if you have libPWMD installed.])
else
    AM_CONDITIONAL(HAVE_LIBPWMD, false)
fi

# We may have a fallback MDA available in case the socket open to the 
# local SMTP listener fails.  Best to use procmail for this, as we know
# it won't try delivering through local SMTP and cause a mail loop.
# Sendmail without the -t option to use the message headers will work too,
# not just for sendmail itself but for workalikes like exim.
#
# Note1: A disadvantage of using procmail is that local alias expansion
# according to /etc/aliases won't get done if we fall back.  This doesn't
# matter in single-drop mode.
#
# Note2: it would be a very bad idea to use any MDA that doesn't return
# a refuse-to-deliver status on disk- or process-table-full
# conditions; mail could get lost that way.  Sendmail and all of the MDAs
# like exim that might be lurking under a sendmail alias) do the right 
# thing in this circumstance.  Matthias Andree warns that procmail does
# not.  
#
# Note3: Defalt value of fallback is now off.  Matthias writes:
#
# 1. there is no way to predict when the fallback is used. With some MTAs
#    (such as those limiting load average), outer circumstances can cause
#    the fallback to kick in.
# 
# 2. the fallback changes fetchmail behaviour in unpredictable ways. It's
#    not only about alias expansion, .forwards to special filters won't
#    work, mail may end up in a different place (users claim "mail loss"
#    for that).
# 
# 3. The claim procmail did the right thing with its exit codes is plain
#    wrong. I've seen procmail exit with code 1 when it should have exited
#    with code 75, like, configuration errors. Procmail is a dangerous
#    beast and is best replaced by maildrop.
# 
# 4. if multiple choices exist (like procmail and maildrop), fetchmail
#    cannot tell which one it should choose. Say, your MTA is configured
#    to use maildrop to deliver to user's mailboxes, if fetchmail then
#    chooses procmail, this is plain wrong.
#

AC_PATH_PROG(procmail, procmail, "", $PATH:/usr/sbin)
AC_PATH_PROG(sendmail, sendmail, "", $PATH:/usr/sbin:/usr/lib)
AC_PATH_PROG(maildrop, maildrop, "", $PATH:/usr/local/bin)

###	use option --disable-fallback to disable fallback MDA
###	use option --enable-fallback=procmail or 
###		   --enable-fallback=sendmail to select
AC_ARG_ENABLE(fallback,
	[  --enable-fallback=procmail    enable procmail as fallback
  --enable-fallback=sendmail    enable /usr/sbin/sendmail as fallback
  --enable-fallback=maildrop    enable maildrop as fallback
  --enable-fallback=no          disable fallback],,[enable_fallback=no])

case "$enable_fallback" in
	sendmail)	if test -z "$sendmail" ; then 
				AC_MSG_ERROR([Sendmail selected as fallback, but not found])
				#not reached
			fi
			AC_DEFINE_UNQUOTED(FALLBACK_MDA, "$sendmail -i %T", Fallback MTA to use if defined)
			AC_MSG_NOTICE(Will use $sendmail as fallback MDA.)
			;;
	procmail)	if test -z "$procmail" ; then
				AC_MSG_ERROR([procmail selected as fallback, but not found])
				#not reached
			fi
			AC_DEFINE_UNQUOTED(FALLBACK_MDA, "$procmail -d %T")
			AC_MSG_NOTICE(Will use $procmail as fallback MDA.)
			;;
	maildrop)	if test -z "$maildrop" ; then
				AC_MSG_ERROR([maildrop selected as fallback, but not found])
				#not reached
			fi
			AC_DEFINE_UNQUOTED(FALLBACK_MDA, "$maildrop -d %T")
			AC_MSG_NOTICE(Will use $maildrop as fallback MDA.)
			;;
	no|unset)	AC_MSG_NOTICE(Will not use a fallback MDA.)
			;;
	auto|yes|set)	if test -n "$sendmail" ; then
				AC_DEFINE_UNQUOTED(FALLBACK_MDA,"$sendmail -i %T")
				AC_MSG_NOTICE(Will use $sendmail as fallback MDA.)
			else
				AC_MSG_WARN(No fallback MDA available.  procmail and maildrop are not eligible)
				AC_MSG_WARN(for automatic fallback MDA configuration for reliability reasons.)
			fi
			;;
	*)		AC_MSG_ERROR([unkown value for --enable-fallback given: $enable_fallback])
			#notreached
			;;
esac

###	use option --disable-POP3 to omit the POP3 support
AC_ARG_ENABLE(POP3,
	[  --disable-POP3          don't compile in POP3 protocol support],
	[with_POP3=$enableval],
	[with_POP3=yes])
test "$with_POP3" = "yes" && AC_DEFINE(POP3_ENABLE,1,Define if you want POP3 support compiled in)
AM_CONDITIONAL(POP3_ENABLE, test "$with_POP3" = yes)

###	use option --disable-IMAP to omit the IMAP support
AC_ARG_ENABLE(IMAP,
	[  --disable-IMAP          don't compile in IMAP protocol support],
	[with_IMAP=$enableval],
	[with_IMAP=yes])
test "$with_IMAP" = "yes" && AC_DEFINE(IMAP_ENABLE,1,Define if you want IMAP support compiled in)
AM_CONDITIONAL(IMAP_ENABLE, test "$with_IMAP" = yes)

###	use option --disable-ETRN to omit the ETRN support
AC_ARG_ENABLE(ETRN,
	[  --disable-ETRN          don't compile in ETRN protocol support],
	[with_ETRN=$enableval],
	[with_ETRN=yes])
test "$with_ETRN" = "yes" && AC_DEFINE(ETRN_ENABLE,1,Define if you want ETRN support compiled in.)
AM_CONDITIONAL(ETRN_ENABLE, test "$with_ETRN" = yes)

###	use option --disable-ODMR to omit the ODMR support
AC_ARG_ENABLE(ODMR,
	[  --disable-ODMR          don't compile in ODMR protocol support],
	[with_ODMR=$enableval],
	[with_ODMR=yes])
test "$with_ODMR" = "yes" && AC_DEFINE(ODMR_ENABLE,1,Define if you want ODMR support compiled in)
AM_CONDITIONAL(ODMR_ENABLE, test "$with_ODMR" = yes)

###	use option --enable-RPA to compile in the RPA support
AC_ARG_ENABLE(RPA,
	[  --enable-RPA            compile in RPA protocol support],
	[with_RPA=$enableval],
	[with_RPA=no])
test "$with_RPA" = "yes" && AC_DEFINE(RPA_ENABLE,1,Define if you want RPA support compiled in)
AM_CONDITIONAL(RPA_ENABLE, test "$with_RPA" = yes)

###	use option --enable-NTLM to compile in the NTLM support
AC_ARG_ENABLE(NTLM,
	[  --enable-NTLM           compile in NTLM authentication support],
	[with_NTLM=$enableval],
	[with_NTLM=no])
test "$with_NTLM" = "yes" && AC_DEFINE(NTLM_ENABLE,1,Define if you want NTLM authentication)
AM_CONDITIONAL(NTLM_ENABLE, test "$with_NTLM" = yes)

###	use option --enable-SDPS to compile in the SDPS support
AC_ARG_ENABLE(SDPS,
	[  --enable-SDPS           compile in SDPS protocol support],
	[with_SDPS=$enableval],
	[with_SDPS=no])
if test "$with_SDPS" = yes ; then
   if test "$with_POP3" != yes ; then
       AC_MSG_WARN([SDPS cannot be enabled with POP3 disabled. Disabling SDPS.])
       with_SDPS=no
   else
       AC_DEFINE(SDPS_ENABLE,1,Define if you want SDPS support compiled in)
   fi
fi
if test "$with_POP3" != yes && test "$with_IMAP"  != yes ; then
    AC_MSG_ERROR([You must enable at least one of POP3 and IMAP.])
fi

AC_CACHE_SAVE

###	use option --enable-opie to compile in the OPIE support
AC_ARG_ENABLE(opie,
	[  --enable-opie           support OTP through the OPIE library],
	[ AC_CHECK_HEADER(opie.h,, [AC_MSG_ERROR([cannot find <opie.h>, which is required for OPIE support.])])
          AC_CHECK_LIB(opie,opiegenerator,, [AC_MSG_ERROR([cannot find libopie, which is required for OPIE support.])])
          with_opie=$enableval],
	[with_opie=no])
test "$with_opie" = "yes" && AC_DEFINE(OPIE_ENABLE,1,Define if you want OPIE support compiled in)

dnl Mostly stolen from gnulib's getaddrinfo.m4
AC_SEARCH_LIBS(getaddrinfo, [nsl socket])
AC_CACHE_CHECK([for getaddrinfo],[fm_cv_getaddrinfo],[
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
  ]], [[getaddrinfo(0, 0, 0, 0);]])],[ fm_cv_getaddrinfo=yes],[ fm_cv_getaddrinfo=no ])
])

if test x"$fm_cv_getaddrinfo" = "xyes"; then  
     AC_DEFINE(HAVE_GETADDRINFO, 1,
      [Define to 1 if you have the getaddrinfo function.])
fi

AC_CACHE_CHECK([for getnameinfo],[fm_cv_getnameinfo],[
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#ifndef NULL
#define NULL 0
#endif
  ]], [[getnameinfo(NULL,0, NULL,0, NULL, 0, 0);]])],[ fm_cv_getnameinfo=yes],[ fm_cv_getnameinfo=no ])
])
if test $fm_cv_getnameinfo = yes ; then
    AC_DEFINE(HAVE_GETNAMEINFO,1,[Define to 1 if your system has getnameinfo()])
fi

AM_CONDITIONAL(NEED_GETADDRINFO, test "$fm_cv_getaddrinfo" != yes)
AM_CONDITIONAL(NEED_GETNAMEINFO, test "$fm_cv_getnameinfo"   != yes)

AC_CHECK_FUNCS(inet_ntop)
dnl Check if getaddrinfo is async-signal-safe - most implementations aren't
if test "$fm_cv_getaddrinfo" = yes ; then
    AC_MSG_CHECKING(if your getaddrinfo is async-signal-safe)
    gai_ts=no
    dnl we have getaddrinfo() - check if the OS is known to have a async-signal-safe implementation
    case $host_os in
	darwin9*)				gai_ts=yes ;;
	linux*)					gai_ts=yes ;;
	freebsd5.5|freebsd6*|freebsd7*)		gai_ts=yes ;;
	solaris2.8|solaris2.9|solaris2.10)	gai_ts=yes ;;
    esac
    AC_MSG_RESULT($gai_ts)
    if test $gai_ts = yes ; then
	AC_DEFINE(GETADDRINFO_ASYNCSAFE, 1, [define to 1 if you know your getaddrinfo function is async-signal-safe])
    fi
fi

# This version of the Kerberos 5 options addresses the follwing issues:
# 
# * Build correctly under Heimdal kerberos if it is compiled with db2 and
#   OpenSSL support (Debian's is)

###    use option --with-kerberos5=DIR to point at a Kerberos 5 directory
### make sure --with-ssl is run before --with-kerberos* !
AC_ARG_WITH(kerberos5,
       [  --with-kerberos5=DIR    point fetchmail compilation at a Kerberos 5 directory],
[
if test "$with_kerberos5" != "no"
then
# Check for a OpenBSD special case
if test "$with_kerberos5" = "yes" && ( test `uname` = "OpenBSD" )
then
  AS_MESSAGE(checking kerberosV for OpenBSD...)
  AC_DEFINE(HEIMDAL,1,Define if you have HEIMDAL kerberos 5)
  AC_DEFINE(KERBEROS_V5,1,Define if you have Kerberos V5)
  CFLAGS="$CFLAGS -I/usr/include/kerberosV"
  LIBS="$LIBS -lasn1 -lkrb5 -lcom_err -lkafs"
elif krb5-config 2> /dev/null >/dev/null ; then
  krb5_prefix=`krb5-config --prefix krb5`
  AC_MSG_RESULT([krb5-config points to kerberosV under $krb5_prefix])
  if test -f ${krb5_prefix}/include/et/com_err.h && \
   ! test -f ${krb5_prefix}/include/com_err.h  ; then
    CFLAGS="$CFLAGS -I${krb5_prefix}/include/et"
  fi
  unset krb5_prefix
  CFLAGS="$CFLAGS `krb5-config --cflags krb5`"
  LIBS="$LIBS `krb5-config --libs krb5`"
  AC_DEFINE(KERBEROS_V5)
else
  if test "$with_kerberos5" != "yes" 
  then
      LDFLAGS="$LDFLAGS -L${with_kerberos5}/lib"
      searchdirs="$with_kerberos5"
  else
      searchdirs="/usr/kerberos /usr/local/krb5 /usr/athena /usr"
  fi
  with_kerberos5=
  for dir in $searchdirs
  do AC_MSG_CHECKING([for Kerberos V in $dir])
     if test -f "$dir/include/krb5.h" || test -f "$dir/include/krb5/krb5.h"
     then
	if test -d "$dir/include/krb5" ; then CPPFLAGS="$CPPFLAGS -I$dir/include/krb5" ; fi
        ac_krblibs=
        if test -f "$dir/include/roken.h" || test -f "$dir/include/krb5/roken.h"
        then
           ac_krblibs="-lasn1 -lroken -lcom_err"
           AC_MSG_RESULT([Heimdal found])
          dnl Attempt to detect if we need to -ldb2 to link Heimdal
          dnl we assume we do if it is available
           AC_CHECK_LIB(db2, db_open, ac_krblibs="$ac_krblibs -ldb2", [],
                ${LDFLAGS})
           AC_CHECK_LIB(des, des_string_to_key, libk5crypto=-ldes,
              AC_CHECK_LIB(crypto, MD5_Init, [],
                AC_MSG_ERROR([DES libraries not found. Try adding --with-ssl to enable OpenSSL support]),
                ${LDFLAGS} ${ac_krblibs}),
           ${LDFLAGS} ${ac_krblibs})
           AC_DEFINE(HEIMDAL)
        else
          AC_MSG_RESULT([found])
          ac_krblibs="-lcom_err"
           AC_CHECK_LIB(crypto,
             krb5_des_string_to_key,
             libk5crypto=-lcrypto,
                AC_CHECK_LIB(k5crypto,
                   krb5_des_string_to_key,
                   libk5crypto=-lk5crypto,
                      AC_MSG_ERROR([Kerberos 5 DES libraries not found]),
                   ${LDFLAGS} ${ac_krblibs}),
                 ${LDFLAGS} ${ac_krblibs})
        fi
        AC_CHECK_LIB(krb5, krb5_init_context,[],
           continue,
           ${LDFLAGS} ${ac_krblibs})
        AC_DEFINE(KERBEROS_V5)
        test "$dir" != "/usr" && CFLAGS="$CFLAGS -I$dir/include"
        LDFLAGS="$LDFLAGS -L$dir/lib"
       LIBS="$LIBS $ac_krblibs $libk5crypto"
        with_kerberos5=$dir
        break
     else
        AC_MSG_RESULT([not found])
     fi
  done
  if test -z "$with_kerberos5" ; then
     AC_MSG_ERROR([Kerberos 5 libraries not found])
  fi
fi
fi
]) dnl --with-kerberos5=DIR

###	use option --with-ssl to compile in the SSL support
AC_ARG_WITH(ssl,
	[  --with-ssl=[DIR]        enable SSL support using libraries in DIR],
	[with_ssl=$withval],
	[with_ssl=no])
test "$with_ssl" != "no" && AC_DEFINE(SSL_ENABLE,1,Define if you want SSL support compiled in)

if test "$with_ssl" = "yes"
then
    #	User didn't specify an SSL location.  Let's look at some common
    #	directories where SSL has been found in the past and try and auto
    #	configure for SSL.  OpenSSL determination will be made later.
    #	This will screw up if an OpenSSL install is located in a later
    #	directory than an older SSLeay install, but the user should fix that
    #	anyways and he can override on the configure line.
    #	Just testing for directories is not sufficient, /usr exists on
    #	all systems!
    for ac_dir in \
      /usr/local/ssl \
      /usr/local \
      /usr/ssl \
      /usr \
      /local/ssl \
      /opt/ssl \
      /opt/csw \
      ; \
    do
        if test -r "$ac_dir/include/openssl/ssl.h" ; then
            with_ssl=$ac_dir
            break;
        fi
    done
fi

if test -n "$with_ssl" -a "$with_ssl" != "no"
then
  # With the autoconfigure above, the only time this is going to be
  # true is going to be when we could not find the headers.  If they
  # are not in system standard locations, we are going to be broken.
  if test "$with_ssl" = "yes"
  then
    # Let's just define the standard location for the SSLeay root
    with_ssl="/usr/local/ssl"
  fi
  if test -r $with_ssl/include/openssl/ssl.h
  then
    ###	ssl.h found under openssl.  Use openssl configuration preferentially,
    AC_MSG_NOTICE(Enabling OpenSSL support in $with_ssl.)
    test "$with_ssl" != "/usr" && CFLAGS="$CFLAGS -I$with_ssl/include"
    ### In Red Hat 9, this file includes a reference to <krb5.h>, so we
    ### force the Kerberos direcory onto the include path so it will build.
    CFLAGS="$CFLAGS -I/usr/kerberos/include"
    ###	OpenBSD comes with ssl headers
  else
    AC_MSG_ERROR([SSL support enabled, but OpenSSL not found])
  fi
  LDFLAGS="$LDFLAGS -L$with_ssl/lib"
  LIBS="$LIBS -lssl -lcrypto"
  dnl check if -ldl is needed
  AC_MSG_CHECKING([for additional library dependencies of SSL])
  found=0
  save_LIBS="$LIBS"
  for i in "" "-ldl" ; do
      LIBS="$LDFLAGS $save_LIBS $i"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <openssl/ssl.h>],[SSL_library_init()])],[found=1; break])
  done
  if test $found = 0 ; then
      AC_MSG_RESULT([error])
      AC_MSG_ERROR([cannot link with SSL - check config.log])
  fi
  LIBS="$save_LIBS $i"
  if test "$i" = "" ; then i="(none)" ; fi
  AC_MSG_RESULT($i)
  dnl XXX FIXME: use pkg-config if available!
  AC_DEFINE(SSL_ENABLE)
else
  AC_MSG_NOTICE(Disabling SSL support.)
fi

###	use option --with-socks=DIR to point at SOCKS library
AC_ARG_WITH(socks,
	[  --with-socks[=DIR]      add built-in SOCKS firewall access],
[
if test "$with_socks" != no
then
    if test "$with_socks" != yes
    then
        LDFLAGS="$LDFLAGS -L$with_socks"
    else
        AC_CHECK_LIB(socks, Rconnect,,
               AC_MSG_ERROR([could not find libsocks which is needed for built-in SOCKS support]))
    fi
    AC_DEFINE(HAVE_SOCKS,1,Define if you want built-in SOCKS support)
    CFLAGS="$CFLAGS -Dconnect=Rconnect -Dgetsockname=Rgetsockname -Dbind=Rbind -Daccept=Raccept -Dlisten=Rlisten -Dselect=Rselect"
    LIBS="-lsocks $LIBS"
fi])

###     use option --with-socks5=DIR to point at SOCKS library
AC_ARG_WITH(socks5,
        [  --with-socks5[=DIR]     add built-in SOCKS5 firewall access],
[
if test "$with_socks5" != no
then
  if test "$with_socks5" != yes
  then
    LDFLAGS="$LDFLAGS -L$with_socks5"
  fi
  ac_savedLDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS $LDFLAGS"
  AC_CHECK_LIB(socks5, SOCKSconnect,,
  	AC_MSG_ERROR([could not find libsocks5 which is needed for built-in SOCKS5 support]))
  AC_DEFINE(HAVE_SOCKS)
  CFLAGS="$CFLAGS -Dconnect=SOCKSconnect -Dgetsockname=SOCKSgetsockname -Dbind=SOCKSbind -Daccept=SOCKSaccept -Dlisten=SOCKSlisten -Dselect=SOCKSselect -Drecvfrom=SOCKSrecvfrom -Dsendto=SOCKSsendto -Drecv=SOCKSrecv -Dsend=SOCKSsend -Dread=SOCKSread -Dwrite=SOCKSwrite -Drresvport=SOCKSrresvport -Dshutdown=SOCKSshutdown -Dlisten=SOCKSlisten -Dclose=SOCKSclose -Ddup=SOCKSdup -Ddup2=SOCKSdup2 -Dgethostbyname=SOCKSgethostbyname"
  AC_CHECK_FUNC(SOCKSfclose, [CFLAGS="$CFLAGS -Dfclose=SOCKSfclose"])
  LDFLAGS="$ac_savedLDFLAGS"
fi])

dnl for libesmtp/ modules:
ACX_WHICH_GETHOSTBYNAME_R

###	use option --with-hesiod=DIR to point at a HESIOD directory
AC_ma_SEARCH_PACKAGE(hesiod, hesiod_getmailhost, /usr/athena /usr /usr/local,hesiod, hesiod.h)

###	use option --with-gssapi=DIR to compile in GSSAPI support
AC_ARG_WITH(gssapi,
	[  --with-gssapi[=DIR]     compile in GSSAPI support using libraries in DIR],
[
if test "$with_gssapi" != "no"
then
  if test "$with_gssapi" = "yes" -a -n "$with_kerberos5"
  then
    with_gssapi=$with_kerberos5
  fi

  if test "$with_gssapi" != "yes" -a -n "$with_gssapi"
  then
    CFLAGS="$CFLAGS -I$with_gssapi/include"
    LDFLAGS="$LDFLAGS -L$with_gssapi/lib"
  fi

  dnl obtain gssapi default libs
  if krb5-config --libs gssapi 2>/dev/null >/dev/null ; then
      LIBS="$LIBS `krb5-config --libs gssapi`"
  else
    AC_CHECK_LIB(gss, gss_check_version, LIBS="$LIBS -lgss", nogss=t)
    if test -n "$nogss"
    then
      # -lgss not found
      if test "$with_gssapi" = yes ; then
	  with_gssapi=/usr
      fi
      if test -f "$with_gssapi/include/roken.h" -o -f "$with_gssapi/include/krb5/roken.h"
      then
         # have roken.h, assume Heimdal
	 case `uname` in
	     NetBSD) LIBS="$LIBS -lkrb5" ;;
	     *)      LIBS="$LIBS -lkrb5 -lasn1 -ldes -lroken -ldb -ldl" ;;
	 esac
         AC_CHECK_LIB(gssapi, gss_init_sec_context,LIBS="$LIBS -lgssapi",
                      AC_MSG_ERROR([could not find libgssapi which is needed for GSSAPI support]), )
         AC_DEFINE(HEIMDAL)
      else
         # no roken.h, assume MIT
         AC_CHECK_LIB(gssapi_krb5, gss_init_sec_context,LIBS="$LIBS -lgssapi_krb5",
                      AC_MSG_ERROR([could not find libgssapi_krb5 which is needed for GSSAPI support]), -lkrb5)
      fi
    fi
  fi
  AC_DEFINE(GSSAPI,1,Define if you want GSSAPI authentication)
  if test "$with_gssapi" != yes ; then
    CPPFLAGS="$CPPFLAGS -I$with_gssapi/include"
  fi
  AC_CHECK_HEADERS(gss.h gssapi.h gssapi/gssapi.h gssapi/gssapi_generic.h)
  if test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi.h, AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,1,Define if you have MIT kerberos))
  else
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi/gssapi.h, AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE))
  fi
fi])

AC_CONFIG_FILES([Makefile po/Makefile.in genlsm.sh])
AC_OUTPUT

dnl Local Variables:
dnl comment-start: "dnl "
dnl comment-end: ""
dnl comment-start-skip: "\\bdnl\\b\\s *"
dnl compile-command: "make configure config.h.in"
dnl End:
