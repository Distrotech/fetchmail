#!/bin/sh
#
# indexgen.sh -- generate current version of fetchmail home page.
#
version=`sed -n <Makefile.in "/VERS=/s/VERS=\([^ 	]*\)/\1/p"`
date=`date "+%d %b %Y"`

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
<a href="http://www.ccil.org/~esr/esr-freeware.html">Freeware</a>
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

Fetchmail is a free, full-featured, robust, well-documented
remote-mail retrieval and forwarding utility intended to be used over
on-demand TCP/IP links (such as SLIP or PPP connections). It supports
every remote-mail protocol now in use on the Internet: POP2, POP3,
RPOP, APOP, KPOP, all flavors of IMAP, and ESMTP ETRN. <P>

Fetchmail retrieves mail from remote mail servers and forwards it via
SMTP, so it can then be be read by normal mail user agents such as
elm(1) or Mail(1).  It allows all your sytem MTA's filtering,
forwarding, and aliasing facilities to work just as they would on
normal mail.<P>

Fetchmail offers better security than any other Unix remote-mail
client.  It supports APOP, KPOP, OTP, Compuserve RPA, and IMAP RFC1731
encrypted authentication methods to avoid sending passwords en
clair.<p>

Fetchmail can be used as a POP/IMAP-to-SMTP gateway for an entire DNS
domain, collecting mail from a single drop box on an ISP and
SMTP-forwarding it based on header addresses. (We don't really
recommend this, though, as it may lose important envelope-header
information.  ETRN or a UUCP connection is better.)<p>

Fetchmail can be started automatically and silently as a system daemon
at boot time.  When running in this mode with a short poll interval,
it is pretty hard for anyone to tell that the incoming mail link is
not a full-time "push" connection.<p>

Fetchmail is easy to configure, fast, and lightweight.  It packs all
its features in less than 90K of core on a Pentium under Linux.<p>

(Fetchmail is the successor of the old popclient utility, which is
officially dead.)<P>

<H1>Where to find out more about fetchmail:</H1>

See the <a href="fetchmail-features.html">Fetchmail Feature List</a> for more
about what fetchmail does.<p>

See the <a href="fetchmail-FAQ.html">HTML Fetchmail FAQ</A> for
troubleshooting help.<p>

See the <a href="http:design-notes.html">Fetchmail Design Notes</a>
for discussion of some of the design choices in fetchmail.<P>

Finally, see the distribution <a href="NEWS">NEWS file</a> for a
description of changes in recent versions.<p>

<H1>How to get fetchmail:</H1>

You can get any of the following here:
<UL>
<LI> <a href="fetchmail-$version.tar.gz">
	Gzipped source archive of fetchmail $version</a>
<LI> <a href="fetchmail-$version-1.i386.rpm">
	Intel binary RPM of fetchmail $version</a>
<LI> <a href="fetchmail-$version-1.src.rpm">
	Source RPM of fetchmail $version</a>
</UL>

(Note that the RPMs don't have the POP2 or Compuserve RPA support
compiled in.  To get that you will have to build from sources.)<p>

The latest version of fetchmail is also carried in the 
<a href="http://sunsite.unc.edu/pub/Linux/system/mail/pop/!INDEX.html">
Sunsite remote mail tools directory</a>.

<H1>Getting help with fetchmail</H1>

There is a fetchmail-friends list for people who want to discuss fixes
and improvements in fetchmail and help co-develop it.  It's at <a
href="mailto:fetchmail-friends@thyrsus.com">fetchmail-friends@thyrsus.com</a>.
There is also an announcements-only list, <em>fetchmail-announce@thyrsus.com</em>.<P>

Both lists are SmartList reflectors; sign up in the usual way with a
message containing the word "subscribe" in the subject line sent to
<a href="mailto:fetchmail-friends-request@thyrsus.com?subject=subscribe">
fetchmail-friends-request@thyrsus.com</a> or
<a href="mailto:fetchmail-announce-request@thyrsus.com?subject=subscribe">
fetchmail-announce-request@thyrsus.com</a>. (Similarly, "unsubscribe"
in the Subject line unsubscribes you, and "help" returns general list help) <p>

Note: before submitting a question to the list, <strong>please read
the <a href="fetchmail-FAQ.html">FAQ</a></strong> (especially item <a
href="http:fetchmail-FAQ.html#G3">G3</a> on how to report bugs).  We
tend to get the same three newbie questions over and over again.  The
FAQ covers them like a blanket.  Actually, I'll answer the most common
one right here: <em>If you've tried everything but can't get multidrop
mode to work, it is almost certainly because your DNS service (or your
provider's) is broken.</em><P>

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
<IT>popclient</IT> utility. It has since come into extremely wide use in the
Internet/Unix/Linux community.  The Red Hat and Debian Linux distributions
include it.  A customized version is used at Whole Earth 'Lectronic
Link. Several large ISPs are known to recommend it to Unix-using SLIP
and PPP customers.<p>

Over three hundred people have participated on the fetchmail beta
list.  While it's hard to count free software users, we can estimate
based on (a) population figures at the WELL and other known fetchmail
sites, (b) the size of the Linux-using ISP customer base, and (c) the
volume of fetchmail-related talk on USENET.  These estimates suggest
that daily fetchmail users number well into the tens of thousands, and
possibly over a hundred thousand.<p>

<H1>The fetchmail paper:</H1>

The fetchmail development project was a sociological experiment as well
as a technical effort.  I ran it as a test of some theories about why the
Linux development model works.<P>

I wrote a paper, <A HREF="../writings/cathedral.html">The Cathedral
And The Bazaar</A>, about these theories and the project. It was well
received at <A HREF="http://www.linux-kongress.de"> Linux Kongress
'97</A> and the <A HREF="http://www.ale.org/showcase"> Atlanta Linux
Expo</A> two weeks later.  I also presented it at Tim O'Reilly's
<A HREF="http://www.ora.com/perlconference">Perl Conference</A>
August 19th-21st 1997.  A lot of people like it.<P>

<H1>Recent releases and where fetchmail is going:</H2>

After 4.0.1 I wrote: "Development has essentially stopped because
there seems to be little more that needs doing."  This turned out to
be not quite true, I've added some minor option switches since, mostly
to deal with weird configuration situations.  We've also fixed a hang
problem with Cyrus IMAP servers and enabled the code to work with the
<a href="fetchmail.FAQ.html#T5">(extremely broken)</a> Microsoft
Exchange POP3 server.  And we've added support for Compuserve RPA.<P>

The present TO-DO list reads:<P>

<UL>
<LI>
Generate bounce messages when delivery is refused.  See RFC1891, RFC1894.

<LI>
More log levels?

<LI>
Use the libmd functions for md5 under Free BSD?  (Low priority.)
</UL>

But these are frills.  I'm not seeing serious user demand for any of them.<P>

Major changes or additions now seem unlikely until there are
significant changes in or additions to the related protocol RFCs.<p>

<H1>Where you can use fetchmail:</H1>

The fetchmail code was developed under Linux, but has also been
extensively tested under 4.4BSD, Solaris, AIX, and NEXTSTEP.  It should be
readily portable to other Unix variants (it uses GNU autoconf).  It is
reported to build and run correctly under AmigaOS and QNX as well.<p>

<H1>Fetchmail's funniest fan letter:</H1>

<A HREF="funny.html">This letter</A> still cracks me up whenever I reread it. 

<H1>The fetchmail button:</H1>

If you use fetchmail and like it, here's a nifty fetchmail button you
can put on your web page:<P>

<center><img src="fetchmail.gif"></center><P>

Thanks to Steve Matuszek for the graphic design.  The hand in the
button (and the larger top-of-page graphic) was actually derived from
a color scan of the fetchmail author's hand. <P>

<H1>Fetchmail mirror sites:</H1>

There is a FTP mirror of the fetchmail FTP directory (not this WWW
home site, just the current sources and RPM) in Japan at
<a href="ftp://ftp.win.or.jp/pub/network/mail/fetchmail">
ftp://ftp.win.or.jp/pub/network/mail/fetchmail</a>.<P>

<HR>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to 
<a href="http://www.ccil.org/~esr/esr-freeware.html">Freeware</a>
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
