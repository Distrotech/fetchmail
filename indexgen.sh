#!/bin/sh
#
# indexgen.sh -- generate current version of fetchmail home page.
#
goldvers="5.0.0"
goldname="5.0.0"
version=`sed -n <Makefile.in "/VERSION *= */s/VERSION *= *\([^ 	]*\)/\1/p"`
date=`date "+%d %b %Y"`

set -- `timeseries | grep -v "%" | head -1`
subscribers=$4
set -- `ls -ks fetchmail`
fetchmailsize=$1

rm -f index.html

# Compute MD5 checksums for security audit
rm -f checksums
for file in fetchmail-$version.tar.gz fetchmail-$version-1.i386.rpm fetchmail-$version-1.src.rpm
do 
    md5sum $file >>checksums
done

if [ $version != $goldvers ]
then
    for file in fetchmail-$goldvers.tar.gz fetchmail-$goldvers-1.i386.rpm fetchmail-$goldvers-1.src.rpm
    do
	md5sum $file >>checksums
    done
fi

cat >index.html <<EOF
<!doctype HTML public "-//W3O//DTD W3 HTML 3.2//EN">
<HTML>
<HEAD>
<TITLE>Fetchmail Home Page</TITLE>
<link rev=made href=mailto:esr@snark.thyrsus.com>
<meta name="description" content="The fetchmail home page.">
<meta name="keywords" content="fetchmail, POP, POP3, IMAP, IMAP2bis, IMAP4, IMAP4rev1, ETRN, OTP, RPA"> 
</HEAD>
<BODY>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to
<a href="http://$WWWVIRTUAL/~esr/software.html">Software</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>$date
</table>
<HR>
<center>
<table border="10">
<tr>
<td>
<center><img src="bighand.gif"></center>
</td>
</tr>
</table>
<H1>The fetchmail Home Page</H1>
</center><P>

<H1>What fetchmail does:</H1>

Fetchmail is a full-featured, robust, well-documented
remote-mail retrieval and forwarding utility intended to be used over
on-demand TCP/IP links (such as SLIP or PPP connections). It supports
every remote-mail protocol now in use on the Internet: POP2, POP3,
RPOP, APOP, KPOP, all flavors of <a
href="http://www.imap.org">IMAP</a>, and ESMTP ETRN. It can even
support IPv6 and IPSEC.<P>

Fetchmail retrieves mail from remote mail servers and forwards it via
SMTP, so it can then be be read by normal mail user agents such as <a
href="http://www.mutt.org/">mutt</a>, elm(1) or BSD Mail.
It allows all your system MTA's filtering, forwarding, and aliasing
facilities to work just as they would on normal mail.<P>

Fetchmail offers better security than any other Unix remote-mail
client.  It supports APOP, KPOP, OTP, Compuserve RPA, and IMAP RFC1731
encrypted authentication methods to avoid sending passwords en
clair. It can be configured to support end-to-end encryption via
tunneling with <a href="http://www.cs.hut.fi/ssh/">ssh, the Secure Shell</a><p>

Fetchmail can be used as a POP/IMAP-to-SMTP gateway for an entire DNS
domain, collecting mail from a single drop box on an ISP and
SMTP-forwarding it based on header addresses. (We don't really
recommend this, though, as it may lose important envelope-header
information.  ETRN or a UUCP connection is better.)<p>

Fetchmail can be started automatically and silently as a system daemon
at boot time.  When running in this mode with a short poll interval,
it is pretty hard for anyone to tell that the incoming mail link is
not a full-time "push" connection.<p>

Fetchmail is easy to configure.  You can edit its dotfile directly, or
use the interactive GUI configurator (fetchmailconf) supplied with the
fetchmail distribution.<P>

Fetchmail is fast and lightweight.  It packs all its standard
features (POP3, IMAP, and ETRN support) in ${fetchmailsize}K of core on a
Pentium under Linux.<p>

Fetchmail is <a href="http://www.opensource.org">open-source</a>
software.  The openness of the sources is your strongest possible
assurance of quality and reliability.<P>

<H1>Where to find out more about fetchmail:</H1>

See the <a href="fetchmail-features.html">Fetchmail Feature List</a> for more
about what fetchmail does.<p>

See the <a href="fetchmail-FAQ.html">HTML Fetchmail FAQ</A> for
troubleshooting help.<p>

See the <a href="design-notes.html">Fetchmail Design Notes</a>
for discussion of some of the design choices in fetchmail.<P>

<H1>How to get fetchmail:</H1>

You can get any of the following leading-edge resources here:
<UL>
<LI> <a href="fetchmail-$version.tar.gz">
	Gzipped source archive of fetchmail $version</a>
<LI> <a href="fetchmail-$version-1.i386.rpm">
	Intel binary RPM of fetchmail $version (uses glibc)</a>
<LI> <a href="fetchmail-$version-1.src.rpm">
	Source RPM of fetchmail $version</a>
</UL>

MD5 <a href="checksums">checksums</a> are available for these files.<p>
EOF

if [ $version != $goldvers ]
then
    cat >>index.html <<EOF

Or you can get the last \`gold' version, $goldname:
<UL>
<LI> <a href="fetchmail-$goldvers.tar.gz">
	Gzipped source archive of fetchmail $goldname</a>
<LI> <a href="fetchmail-$goldvers-1.i386.rpm">
	Intel binary RPM of fetchmail $goldname (uses glibc)</a>
<LI> <a href="fetchmail-$goldvers-1.alpha.rpm">
	Alpha binary RPM of fetchmail $goldname (uses glibc)</a>
<LI> <a href="fetchmail-$goldvers-1.src.rpm">
	Source RPM of fetchmail $goldname</a>
</UL>
For differences between the leading-edge $version and gold $goldname versions,
see the distribution <a href="NEWS">NEWS</a> file.<p>
EOF
fi

cat >>index.html <<EOF
(Note that the RPMs don't have the POP2, OTP, IPv6, Kerberos, GSSAPI,
Compuserve RPA, or GNU gettext internationalization support compiled
in.  To get any of these you will have to build from sources.)<p>

The latest version of fetchmail is also carried in the 
<a href="http://sunsite.unc.edu/pub/Linux/system/mail/pop/!INDEX.html">
Sunsite remote mail tools directory</a>.

<H1>Getting help with fetchmail:</H1>

There is a fetchmail-friends list for people who want to discuss fixes
and improvements in fetchmail and help co-develop it.  It's at <a
href="mailto:fetchmail-friends@ccil.org">fetchmail-friends@ccil.org</a>.
There is also an announcements-only list, <em>fetchmail-announce@ccil.org</em>.<P>

Both lists are SmartList reflectors; sign up in the usual way with a
message containing the word "subscribe" in the subject line sent to
<a href="mailto:fetchmail-friends-request@ccil.org?subject=subscribe">
fetchmail-friends-request@ccil.org</a> or
<a href="mailto:fetchmail-announce-request@ccil.org?subject=subscribe">
fetchmail-announce-request@ccil.org</a>. (Similarly, "unsubscribe"
in the Subject line unsubscribes you, and "help" returns general list help) <p>

Note: before submitting a question to the list, <strong>please read
the <a href="fetchmail-FAQ.html">FAQ</a></strong> (especially item <a
href="http:fetchmail-FAQ.html#G3">G3</a> on how to report bugs).  We
tend to get the same three newbie questions over and over again.  The
FAQ covers them like a blanket.<P>

Fetchmail was written and is maintained by <a
href="../index.html">Eric S. Raymond</a>.  <a
href="mailto:funk+@osu.edu">Rob Funk</a>, <a
href="mailto:alberty@apexxtech.com">Al Youngwerth</a> and <a
href="mailto:imdave@mcs.net">Dave Bodenstab</a> are fetchmail's
designated backup maintainers.  Other backup maintainers may be added
in the future, in order to ensure continued support should Eric S.
Raymond drop permanently off the net for any reason.<P>

<H1>Who uses fetchmail:</H1>

Fetchmail entered full production status with the 2.0 version in
November 1996 after about five months of evolution from the ancestral
<IT>popclient</IT> utility. It has since come into extremely wide use
in the Internet/Unix/Linux community.  The Red Hat, Debian and
S.u.S.e. Linux distributions include it.  A customized version is used
at Whole Earth 'Lectronic Link. Several large ISPs are known to
recommend it to Unix-using SLIP and PPP customers.<p>

Over seven hundred people have participated on the fetchmail beta list
(at time of current release there were $subscribers on the friends and
announce lists).  While it's hard to count the users of open-source
software, we can estimate based on (a) population figures at the WELL
and other known fetchmail sites, (b) the size of the Linux-using ISP
customer base, and (c) the volume of fetchmail-related talk on USENET.
These estimates suggest that daily fetchmail users number well into
the tens of thousands, and possibly over a hundred thousand.<p>

<H1>The fetchmail paper:</H1>

The fetchmail development project was a sociological experiment as well
as a technical effort.  I ran it as a test of some theories about why the
Linux development model works.<P>

I wrote a paper, <A
HREF="http://www.tuxedo.org/~esr/writings/cathedral-bazaar/">The
Cathedral And The Bazaar</A>, about these theories and the project.
The paper became quite popular and (to my continuing astonishment) may
have actually helped change the world.  Chase the title link, above,
to its page.<P>

<H1>Recent releases and where fetchmail is going:</H1>

Fetchmail is now sufficiently stable and effective that I'm getting
very little pressure to fix things or add features.  Development has
slowed way down, release frequency has dropped off, and we're
basically in maintainance mode.  Barring any urgent bug fixes, my 
intention is to leave 5.0.0 alone for several months.<p>

Major changes or additions therefore seem unlikely until there are
significant changes in or additions to the related protocol RFCs.  One
development that would stimulate a new release almost instantly is the
deployment of a standard lightweight encrypted authentication method
for IMAP sessions.<p>

<H1>Where you can use fetchmail:</H1>

The fetchmail code was developed under Linux, but has also been
extensively tested under 4.4BSD, SunOS, Solaris, AIX, and NEXTSTEP.  It
should be readily portable to other Unix variants (it requires only
POSIX plus BSD sockets, and uses GNU autoconf).<P>

Fetchmail is supported only for Unix by its official maintainers.
However, it is reported to build and run correctly under AmigaOS and
QNX as well. A <a href="http://studentweb.tulane.edu/%7Ejmcbray/os2">beta
OS/2 port</a> is available from Jason F. McBrayer.<p>

<H1>Related resources</H1>

Jochen Hayek is developing a set of
<a href="http://www.ACM.org/~Jochen_Hayek/JHimap_utils/">
IMAP tools in Python</a> that read your .fetchmailrc file and are
designed to work with fetchmail.   Jochen's tools can report selected
header lines, or move incoming messages to named mailboxes based on
the contents of headers.<p>

Hugo Rabson has written a script called \`hotmole' that can retrieve
Hotmail mail via the web using Lynx.  The script is available on <a
href="http://www.jin-sei-kai.demon.co.uk/hugo/linux.html"> Hugo
Rabson's Linux page</a>.<P>

<H1>Fetchmail's funniest fan letter:</H1>

<A HREF="funny.html">This letter</A> still cracks me up whenever I reread it. 

<H1>The fetchmail button:</H1>

If you use fetchmail and like it, here's a nifty fetchmail button you
can put on your web page:<P>

<center><img src="fetchmail.gif"></center><P>

Thanks to <a href="http://www.gl.umbc.edu/~smatus1/">Steve
Matuszek</a> for the graphic design.  The hand in the button (and the
larger top-of-page graphic) was actually derived from a color scan of
the fetchmail author's hand. <P>

<H1>Fetchmail mirror sites:</H1>

There is a FTP mirror of the fetchmail FTP directory (not this WWW
home site, just the current sources and RPM) in Japan at
<a href="ftp://ftp.win.or.jp/pub/network/mail/fetchmail">
ftp://ftp.win.or.jp/pub/network/mail/fetchmail</a>.<P>

<HR>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to 
<a href="http://$WWWVIRTUAL/~esr/software.html">Software</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>$date
</table>

<P><ADDRESS>Eric S. Raymond <A HREF="mailto:esr@thyrsus.com">&lt;esr@snark.thyrsus.com&gt;</A></ADDRESS>
</BODY>
</HTML>
EOF

# The following sets edit modes for GNU EMACS
# Local Variables:
# mode:html
# truncate-lines:t
# End:
