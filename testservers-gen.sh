#!/bin/sh

date=`date`
cat <<EOF
<!DOCTYPE HTML public "-//W3O//DTD W3 HTML 4.0//EN">
<HTML>
<HEAD>
<link rev=made href="mailto:esr@snark.thyrsus.com">
<meta name="description" content="">
<meta name="keywords" content=""> 
<TITLE>Fetchmail's Test List</TITLE>
</HEAD>
<BODY>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to <a href="/~esr">Eric's Home Page</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>${date}
</table>
<HR>
<H1 ALIGN=CENTER>Fetchmail's Test List</H1>

Here are the server types on my regression-test list:<p>

<table border=1 with=80% align=center>
<tr>
<td><strong>Protocol & Version</strong></td>
<td><strong>Special Options:</strong></td>
<td><strong>Name:</strong></td>
</tr>
EOF
torturetest.py -t
cat <<EOF
</table>

<p>
If you control a post-office server that is not one of the types listed
here, please consider lending me a test account.  Note that I do <em>not</em>
need shell access, just the permissions to send mail to a mailbox the server
looks at and to fetch mail off of it.<P>
<p>
I'd like to have weird things like a POP2 server and broken things like
Microsoft Exchange on here. These are the real robustness tests.
<HR>
<table width="100%" cellpadding=0><tr>
<td width="30%">Back to <a href="/~esr">Eric's Home Page</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>${dateQ}
</table>

<P><ADDRESS>Eric S. Raymond <A HREF="mailto:esr@thyrsus.com">&lt;esr@thyrsus.com&gt;</A></ADDRESS>
</BODY>
</HTML>
EOF

