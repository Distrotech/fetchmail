#!/bin/sh

date=`date`
cat <<EOF
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<link rev=made href="mailto:esr@snark.thyrsus.com"/>
<meta name="description" content=""/>
<meta name="keywords" content=""/> 
<title>Fetchmail's Test List</title>
</head>
<body>
<table width="100%" cellpadding=0 summary="Canned page header"><tr>
<td width="30%">Back to <a href="/~esr">Eric's Home Page</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>${date}
</tr></table>
<hr />
<h1>Fetchmail's Test List</h1>

<p>Here are the server types on my regression-test list:</p>

<table border=1 width=80% align=center summary="Server list">
<tr>
<td><strong>Protocol &amp; Version:</strong></td>
<td><strong>Special Options:</strong></td>
</tr>
EOF
torturetest.py -t
cat <<EOF
</tr></table>

<p>If you control a post-office server that is not one of the types listed
here, please consider lending me a test account.  Note that I do <em>not</em>
need shell access, just the permissions to send mail to a mailbox the server
looks at and to fetch mail off of it.</p>

<p>I'd like to have weird things like a POP2 server on here.  Also more
closed-source servers because they tend to be broken in odd
ways. These are the real robustness tests.</p>

<hr />
<table width="100%" cellpadding=0 summary="Canned page header"><tr>
<td width="30%">Back to <a href="/~esr">Eric's Home Page</a>
<td width="30%" align=center>Up to <a href="/~esr/sitemap.html">Site Map</a>
<td width="30%" align=right>${date}
</tr></table>

<br clear="left" />
<ADDRESS>Eric S. Raymond <A HREF="mailto:esr@thyrsus.com">&lt;esr@thyrsus.com&gt;</A></ADDRESS>
</BODY>
</HTML>
EOF

