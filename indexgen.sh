#!/bin/sh
#
# indexgen.sh -- generate current version of fetchmail home page.
#
goldvers="5.9.0"
goldname="5.9.0"
version=`sed -n <Makefile.in "/VERSION *= */s/VERSION *= *\([^ 	]*\)/\1/p"`
date=`date "+%d %b %Y"`

set -- `timeseries | grep -v "[%#]" | head -1`
subscribers=$4
make fetchmail
set -- `ls -ks fetchmail`
fetchmailsize=$1
set -- `(cd /lib; ls libc-*)`
glibc=`echo $1 | sed 's/libc-\(.*\)\.so/\1/'`
glibc="glibc-$glibc"

rm -f index.html

# Compute MD5 checksums for security audit
rm -f checksums
for file in fetchmail-$version.tar.gz fetchmail-$version-1.i386.rpm fetchmail-$version-1.src.rpm
do 
    md5sum $file >>checksums
done

if [ $version != $goldvers ]
then
    for file in /usr/src/redhat/SOURCES/fetchmail-$goldvers.tar.gz /usr/src/redhat/RPMS/i386/fetchmail-$goldvers-1.i386.rpm /usr/src/redhat/SRPMS/fetchmail-$goldvers-1.src.rpm
    do
	md5sum $file | sed -e "s: .*/:  :" >>checksums
    done
fi

# Cryptographically sign checksums 
su esr <<EOF
gpg --clearsign checksums
mv checksums.asc checksums
gpg --detach-sign --armor fetchmail-$version.tar.gz
EOF

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
<td width="30%" align=center>Up to <a href="http://$WWWVIRTUAL/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>$date
</table>
<HR>
<center>
<table border="10">
<tr>
<td>
<center><img src="bighand.png"></center>
</td>
</tr>
</table>
<H1>The fetchmail Home Page</H1>
</center><P>

<p><b>Note: if you are a stranded fetchmail.com user, we're sorry but
we have nothing to do with that site and cannot help you.  It's just an
unfortunate coincidence of names.</b>

<H1>What fetchmail does:</H1>

<P>Fetchmail is a full-featured, robust, well-documented
remote-mail retrieval and forwarding utility intended to be used over
on-demand TCP/IP links (such as SLIP or PPP connections). It supports
every remote-mail protocol now in use on the Internet: POP2, POP3,
RPOP, APOP, KPOP, all flavors of <a
href="http://www.imap.org">IMAP</a>, ETRN, and ODMR. It can even
support IPv6 and IPSEC.</P>

<P>Fetchmail retrieves mail from remote mail servers and forwards it via
SMTP, so it can then be be read by normal mail user agents such as <a
href="http://www.mutt.org/">mutt</a>, elm(1) or BSD Mail.
It allows all your system MTA's filtering, forwarding, and aliasing
facilities to work just as they would on normal mail.</P>

<P>Fetchmail offers better security than any other Unix remote-mail
client.  It supports APOP, KPOP, OTP, Compuserve RPA, Microsoft NTLM,
and IMAP RFC1731 encrypted authentication methods including CRAM-MD5
to avoid sending passwords en clair. It can be configured to support
end-to-end encryption via tunneling with <a
href="http://www.openssh.com/">ssh, the Secure Shell</a>.</P>

<P>Fetchmail can be used as a POP/IMAP-to-SMTP gateway for an entire DNS
domain, collecting mail from a single drop box on an ISP and
SMTP-forwarding it based on header addresses. (We don't really
recommend this, though, as it may lose important envelope-header
information.  ETRN or a UUCP connection is better.)</P>

<P>Fetchmail can be started automatically and silently as a system daemon
at boot time.  When running in this mode with a short poll interval,
it is pretty hard for anyone to tell that the incoming mail link is
not a full-time "push" connection.</P>

<P>Fetchmail is easy to configure.  You can edit its dotfile directly, or
use the interactive GUI configurator (fetchmailconf) supplied with the
fetchmail distribution.  It is also directly supported in linuxconf
versions 1.16r8 and later.</P>

<P>Fetchmail is fast and lightweight.  It packs all its standard
features (POP3, IMAP, and ETRN support) in ${fetchmailsize}K of core on a
Pentium under Linux.</P>

<P>Fetchmail is <a href="http://www.opensource.org">open-source</a>
software.  The openness of the sources is your strongest possible
assurance of quality and reliability.</P>

<P><H1>Where to find out more about fetchmail:</H1>

<P>See the <a href="fetchmail-features.html">Fetchmail Feature List</a> for more
about what fetchmail does.</P>

<P>See the on-line <a href="fetchmail-man.html">manual page</a> for
basics.</P>

<P>See the <a href="fetchmail-FAQ.html">HTML Fetchmail FAQ</A> for
troubleshooting help.</P>

<P>See the <a href="design-notes.html">Fetchmail Design Notes</a>
for discussion of some of the design choices in fetchmail.</P>

<P>See the project's <a href="todo.html">To-Do list</a> for indications
of known problems and requested features.</P>

<H1>How to get fetchmail:</H1>

<P>You can get any of the following leading-edge resources here:</P>
<UL>
<LI> <a href="fetchmail-$version.tar.gz">
	Gzipped source archive of fetchmail $version</a>
<LI> <a href="fetchmail-$version-1.i386.rpm">
	Intel binary RPM of fetchmail $version (uses $glibc)</a>
<LI> <a href="fetchmail-$version-1.src.rpm">
	Source RPM of fetchmail $version</a>
</UL>

<P>The <a href="fetchmail-$version.tar.gz.asc">detached GPG
signature</a> for the binary tarball can be used to check it for
correctness, with the command</P>

<listing>
gpg --verify fetchmail-$version.tar.gz.asc fetchmail-$version.tar.gz
</listing>

<P>MD5 <a href="checksums">checksums</a> are available for these files; the
checksum file is cryptographically signed and can be verified with the
command:</P>

<listing>
gpg --verify checksums.asc
</listing>

EOF

if [ $version != $goldvers ]
then
    cat >>index.html <<EOF

<P>Or you can get the last \`gold' version, $goldname:</P>
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
<P>The <a href="fetchmail-$goldvers.tar.gz.asc">detached GPG signature</a> for the
binary tarball can be used to check it for correctness, with the command</P>

<listing>
gpg --verify fetchmail-$goldvers.tar.gz.asc fetchmail-$goldvers.tar.gz
</listing>

<P>For differences between the leading-edge $version and gold $goldname versions,
see the distribution <a href="NEWS">NEWS</a> file.</P>
EOF
fi

cat >>index.html <<EOF
<P>(Note that the binary RPMs don't have the POP2, OTP, IPv6, Kerberos,
GSSAPI, Compuserve RPA, Microsoft NTLM, or GNU gettext
internationalization support compiled in.  To get any of these you
will have to build from sources.)</P>

<P>The latest version of fetchmail is also carried in the 
<a href="http://metalab.unc.edu/pub/Linux/system/mail/pop/!INDEX.html">
Metalab remote mail tools directory</a>.</P>

<H1>Getting help with fetchmail:</H1>

<P>There is a fetchmail-friends list for people who want to discuss fixes
and improvements in fetchmail and help co-develop it.  It's a MailMan
list, which you can sign up for at <a
<a href="http://lists.ccil.org/mailman/listinfo/fetchmail-friends">
fetchmail-friends@ccil.org</a>.
There is also an announcements-only list, 
<a href="http://lists.ccil.org/mailman/listinfo/fetchmail-announce">
fetchmail-announce@lists.ccil.org</a>.</P>

<P>Note: before submitting a question to the list, <strong>please read
the <a href="fetchmail-FAQ.html">FAQ</a></strong> (especially item <a
href="http:fetchmail-FAQ.html#G3">G3</a> on how to report bugs).  We
tend to get the same three newbie questions over and over again.  The
FAQ covers them like a blanket.</P>

<P>Fetchmail was written and is maintained by <a
href="../index.html">Eric S. Raymond</a>.  There are some designated
backup maintainers (<a href="mailto:funk+@osu.edu">Rob Funk</a>, <a
href="http://www.dallas.net/~fox/">David DeSimone aka Fuzzy Fox</a>,
<a href="mailto:imdave@mcs.net">Dave Bodenstab</a>).  Other backup
maintainers may be added in the future, in order to ensure continued
support should Eric S.  Raymond drop permanently off the net for any
reason.</P>

<H1>You can help improve fetchmail:</H1>

<P>I welcome your code contributions.  But even if you don't write code,
you can help fetchmail improve.</P>

<P>If you administer a site that runs a post-office server, you may be
able help improve fetchmail by lending me a test account on your site.
Note that I do not need a shell account for this purpose, just a 
maildrop.  Nor am I interested in collecting maildrops per se --
what I'm collecting is different <em>kinds of servers</em>.</P>

<P>Before each release, I run a test harness that sends date-stamped 
test mail to each site on my regression-test list, then tries to
retrieve it.  Please take a look at my <a href="testservers.html">
list of test servers</a>.  If you can lend me an account on a kind
of server that is <em>not</em> already on this list, please do.</P>

<H1>Who uses fetchmail:</H1>

<P>Fetchmail entered full production status with the 2.0.0 version in
November 1996 after about five months of evolution from the ancestral
<IT>popclient</IT> utility. It has since come into extremely wide use
in the Internet/Unix/Linux community.  The Red Hat, Debian and
S.u.S.e. Linux distributions and their derivatives all include it.  A
customized version is used at Whole Earth 'Lectronic Link. Several
large ISPs are known to recommend it to Unix-using SLIP and PPP
customers.</P>

<P>Somewhere around a thousand people have participated on the fetchmail
beta lists (at time of current release there were $subscribers on the
friends and announce lists).  While it's hard to count the users of
open-source software, we can estimate based on (a) population figures
at the WELL and other known fetchmail sites, (b) the size of the
Linux-using ISP customer base, and (c) the volume of fetchmail-related
talk on USENET.  These estimates suggest that daily fetchmail users
number well into the hundreds of thousands, and possibly over a million.</P>

<H1>The sociology of fetchmail:</H1>

<P>The fetchmail development project was a sociological experiment as well
as a technical effort.  I ran it as a test of some theories about why the
Linux development model works.</P>

<P>I wrote a paper, <A
HREF="http://www.tuxedo.org/~esr/writings/cathedral-bazaar/">The
Cathedral And The Bazaar</A>, about these theories and the project.
I developed the line of analysis it suggested in two later essays.
These papers became quite popular and (to my continuing astonishment) may
have actually helped change the world.  Chase the title link, above,
for links to all three papers.</P>

<P>I have done some analysis on the information in the project NEWS file.
You can view a <a href="history.html">statistical history</a> showing
levels of participation and release frequency over time.</P>

<H1>Recent releases and where fetchmail is going:</H1>

<p>Fetchmail is now sufficiently stable and effective that I'm getting
very little pressure to fix things or add features.  Development has
slowed way down, release frequency has dropped off, and we're
basically in maintainance mode.</P>

<P>Major changes or additions therefore seem unlikely until there are
significant changes in or additions to the related protocol RFCs.  One
development that would stimulate a new release almost instantly is the
deployment of a standard lightweight encrypted authentication method
for IMAP sessions.</P>

<H1>Where you can use fetchmail:</H1>

<P>The fetchmail code was developed under Linux, but has also been
extensively tested under 4.4BSD, SunOS, Solaris, AIX, and NEXTSTEP.  It
should be readily portable to other Unix variants (it requires only
POSIX plus BSD sockets, and uses GNU autoconf).</P>

<P>Fetchmail is supported only for Unix by its official maintainers.
However, it is reported to build and run correctly under BeOS,
AmigaOS, Rhapsody, and QNX as well.</P>

<H1>Related resources:</H1>

<P>Jochen Hayek is developing a set of
<a href="http://www.ACM.org/~Jochen_Hayek/JHimap_utils/">
IMAP tools in Python</a> that read your .fetchmailrc file and are
designed to work with fetchmail.   Jochen's tools can report selected
header lines, or move incoming messages to named mailboxes based on
the contents of headers.</P>

<P>Scott Bronson has written a fetchmail plugin (actually, a specialist
MDA) called <a
href="http://www.trestle.com/linux/trestlemail/">trestlemail</a> that
helps redirect multidrop mail.</P>

<P>Donncha O Caoihm has written a Perl script called 
<a href="http://cork.linux.ie/projects/install-sendmail/">install-sendmail</a>
that assists you in installing sendmail and fetchmail together/</P>

<P>Peter Hawkins has written a script called <a
href="http://www.hawkins.emu.id.au/gotmail/">gotmail</a>
that can retrieve Hotmail. Another script, 
<a href="http://yosucker.sourceforge.net">yosucker</a>, can retrieve
Yahoo webmail.</P>

<P>A hacker identifying himself simply as \`Steines' has written a
filter which rewrites the to-line with a line which only includes
receipients for a given domain and renames the old to-line. It also
rewrites the domainpart of addresses if the offical domain is
different to local domain. You can find it <a 
href="http://www.steines.com/mailf/">here</a>.</P>

<H1>Fetchmail's funniest fan letter:</H1>

<A HREF="funny.html">This letter</A> still cracks me up whenever I reread it. 

<H1>The fetchmail button:</H1>

<P>If you use fetchmail and like it, here's a nifty fetchmail button you
can put on your web page:</P>

<P><center><img src="fetchmail.png"></center></P>

<P>Thanks to <a href="http://www.gl.umbc.edu/~smatus1/">Steve
Matuszek</a> for the graphic design.  The hand in the button (and the
larger top-of-page graphic) was actually derived from a color scan of
the fetchmail author's hand. </P>

<H1>Fetchmail mirror sites:</H1>

<P>There is a FTP mirror of the current sources and RPMs in Japan at
<a href="ftp://ftp.win.ne.jp/pub/network/mail/fetchmail">
ftp://ftp.win.ne.jp/pub/network/mail/fetchmail</a>.

<H1>Reviews and Awards</H1>

<P>Fetchmail was DaveCentral's Best Of Linux winner for
<a href="http://linux.davecentral.com/bol_19990630.html">June 30 1999</a>.</P>

<P>Fetchmail was a five-star Editor's Pick at Softlandindia.</P>

<HR>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to 
<a href="http://$WWWVIRTUAL/~esr/software.html">Software</a>
<td width="30%" align=center>Up to <a href="http://$WWWVIRTUAL/~esr/sitemap.html">Site Map</a>
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
