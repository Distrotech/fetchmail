/*
 * imap.c -- IMAP2bis/IMAP4 protocol methods
 *
 * Copyright 1997 by Eric S. Raymond
 * For license terms, see the file COPYING in this directory.
 */

#include  "config.h"
#include  <stdio.h>
#include  <string.h>
#include  <ctype.h>
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#include  "fetchmail.h"
#include  "socket.h"

#ifdef KERBEROS_V4
#if defined (__bsdi__)
#include <des.h>
#define krb_get_err_text(e) (krb_err_txt[e])
#endif
#if defined (__FreeBSD__) || defined(__linux__)
#define krb_get_err_text(e) (krb_err_txt[e])
#endif
#include <krb.h>
#endif /* KERBEROS_V4 */

#ifdef GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#endif

#ifndef strstr		/* glibc-2.1 declares this as a macro */
extern char *strstr();	/* needed on sysV68 R3V7.1. */
#endif /* strstr */

/* imap_version values */
#define IMAP2		-1	/* IMAP2 or IMAP2BIS, RFC1176 */
#define IMAP4		0	/* IMAP4 rev 0, RFC1730 */
#define IMAP4rev1	1	/* IMAP4 rev 1, RFC2060 */

static int count, seen, recent, unseen, deletions,expunged, imap_version;

int imap_ok(int sock, char *argbuf)
/* parse command response */
{
    char buf [POPBUFSIZE+1];

    seen = 0;
    do {
	int	ok;

	if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);

	/* interpret untagged status responses */
	if (strstr(buf, "EXISTS"))
	    count = atoi(buf+2);
	if (strstr(buf, "RECENT"))
	    recent = atoi(buf+2);
	if (strstr(buf, "UNSEEN"))
	{
	    char	*cp;

	    /*
	     * Handle both "* 42 UNSEEN" (if tha ever happens) and 
	     * "* OK [UNSEEN 42] 42". Note that what this gets us is
	     * a minimum index, not a count.
	     */
	    unseen = 0;
	    for (cp = buf; *cp && !isdigit(*cp); cp++)
		continue;
	    unseen = atoi(cp);
	}
	if (strstr(buf, "FLAGS"))
	    seen = (strstr(buf, "Seen") != (char *)NULL);
    } while
	(tag[0] != '\0' && strncmp(buf, tag, strlen(tag)));

    if (tag[0] == '\0')
    {
	if (argbuf)
	    strcpy(argbuf, buf);
	return(PS_SUCCESS); 
    }
    else
    {
	char	*cp;

	/* skip the tag */
	for (cp = buf; !isspace(*cp); cp++)
	    continue;
	while (isspace(*cp))
	    cp++;

	if (strncmp(cp, "OK", 2) == 0)
	{
	    if (argbuf)
		strcpy(argbuf, cp);
	    return(PS_SUCCESS);
	}
	else if (strncmp(cp, "BAD", 2) == 0)
	    return(PS_ERROR);
	else
	    return(PS_PROTOCOL);
    }
}

#ifdef KERBEROS_V4
#if SIZEOF_INT == 4
typedef	int	int32;
#elif SIZEOF_SHORT == 4
typedef	short	int32;
#elif SIZEOF_LONG == 4
typedef	long	int32;
#else
#error Cannot deduce a 32-bit-type
#endif

static int do_rfc1731(int sock, char *truename)
/* authenticate as per RFC1731 -- note 32-bit integer requirement here */
{
    int result = 0, len;
    char buf1[4096], buf2[4096];
    union {
      int32 cint;
      char cstr[4];
    } challenge1, challenge2;
    char srvinst[INST_SZ];
    char *p;
    char srvrealm[REALM_SZ];
    KTEXT_ST authenticator;
    CREDENTIALS credentials;
    char tktuser[MAX_K_NAME_SZ+1+INST_SZ+1+REALM_SZ+1];
    char tktinst[INST_SZ];
    char tktrealm[REALM_SZ];
    des_cblock session;
    des_key_schedule schedule;

    gen_send(sock, "AUTHENTICATE KERBEROS_V4");

    /* The data encoded in the first ready response contains a random
     * 32-bit number in network byte order.  The client should respond
     * with a Kerberos ticket and an authenticator for the principal
     * "imap.hostname@realm", where "hostname" is the first component
     * of the host name of the server with all letters in lower case
     * and where "realm" is the Kerberos realm of the server.  The
     * encrypted checksum field included within the Kerberos
     * authenticator should contain the server provided 32-bit number
     * in network byte order.
     */

    if (result = gen_recv(sock, buf1, sizeof buf1)) {
	return result;
    }

    len = from64tobits(challenge1.cstr, buf1);
    if (len < 0) {
	error(0, -1, "could not decode initial BASE64 challenge");
	return PS_AUTHFAIL;
    }

    /* Client responds with a Kerberos ticket and an authenticator for
     * the principal "imap.hostname@realm" where "hostname" is the
     * first component of the host name of the server with all letters
     * in lower case and where "realm" is the Kerberos realm of the
     * server.  The encrypted checksum field included within the
     * Kerberos authenticator should contain the server-provided
     * 32-bit number in network byte order.
     */

    strncpy(srvinst, truename, (sizeof srvinst)-1);
    srvinst[(sizeof srvinst)-1] = '\0';
    for (p = srvinst; *p; p++) {
      if (isupper(*p)) {
	*p = tolower(*p);
      }
    }

    strncpy(srvrealm, (char *)krb_realmofhost(srvinst), (sizeof srvrealm)-1);
    srvrealm[(sizeof srvrealm)-1] = '\0';
    if (p = strchr(srvinst, '.')) {
      *p = '\0';
    }

    result = krb_mk_req(&authenticator, "imap", srvinst, srvrealm, 0);
    if (result) {
	error(0, -1, "krb_mq_req: %s", krb_get_err_text(result));
	return PS_AUTHFAIL;
    }

    result = krb_get_cred("imap", srvinst, srvrealm, &credentials);
    if (result) {
	error(0, -1, "krb_get_cred: %s", krb_get_err_text(result));
	return PS_AUTHFAIL;
    }

    memcpy(session, credentials.session, sizeof session);
    memset(&credentials, 0, sizeof credentials);
    des_key_sched(session, schedule);

    result = krb_get_tf_fullname(TKT_FILE, tktuser, tktinst, tktrealm);
    if (result) {
	error(0, -1, "krb_get_tf_fullname: %s", krb_get_err_text(result));
	return PS_AUTHFAIL;
    }

    if (strcmp(tktuser, user) != 0) {
	error(0, -1, "principal %s in ticket does not match -u %s", tktuser,
		user);
	return PS_AUTHFAIL;
    }

    if (tktinst[0]) {
	error(0, 0, "non-null instance (%s) might cause strange behavior",
		tktinst);
	strcat(tktuser, ".");
	strcat(tktuser, tktinst);
    }

    if (strcmp(tktrealm, srvrealm) != 0) {
	strcat(tktuser, "@");
	strcat(tktuser, tktrealm);
    }

    result = krb_mk_req(&authenticator, "imap", srvinst, srvrealm,
	    challenge1.cint);
    if (result) {
	error(0, -1, "krb_mq_req: %s", krb_get_err_text(result));
	return PS_AUTHFAIL;
    }

    to64frombits(buf1, authenticator.dat, authenticator.length);
    if (outlevel == O_VERBOSE) {
	error(0, 0, "IMAP> %s", buf1);
    }
    SockWrite(sock, buf1, strlen(buf1));
    SockWrite(sock, "\r\n", 2);

    /* Upon decrypting and verifying the ticket and authenticator, the
     * server should verify that the contained checksum field equals
     * the original server provided random 32-bit number.  Should the
     * verification be successful, the server must add one to the
     * checksum and construct 8 octets of data, with the first four
     * octets containing the incremented checksum in network byte
     * order, the fifth octet containing a bit-mask specifying the
     * protection mechanisms supported by the server, and the sixth
     * through eighth octets containing, in network byte order, the
     * maximum cipher-text buffer size the server is able to receive.
     * The server must encrypt the 8 octets of data in the session key
     * and issue that encrypted data in a second ready response.  The
     * client should consider the server authenticated if the first
     * four octets the un-encrypted data is equal to one plus the
     * checksum it previously sent.
     */
    
    if (result = gen_recv(sock, buf1, sizeof buf1))
	return result;

    /* The client must construct data with the first four octets
     * containing the original server-issued checksum in network byte
     * order, the fifth octet containing the bit-mask specifying the
     * selected protection mechanism, the sixth through eighth octets
     * containing in network byte order the maximum cipher-text buffer
     * size the client is able to receive, and the following octets
     * containing a user name string.  The client must then append
     * from one to eight octets so that the length of the data is a
     * multiple of eight octets. The client must then PCBC encrypt the
     * data with the session key and respond to the second ready
     * response with the encrypted data.  The server decrypts the data
     * and verifies the contained checksum.  The username field
     * identifies the user for whom subsequent IMAP operations are to
     * be performed; the server must verify that the principal
     * identified in the Kerberos ticket is authorized to connect as
     * that user.  After these verifications, the authentication
     * process is complete.
     */

    len = from64tobits(buf2, buf1);
    if (len < 0) {
	error(0, -1, "could not decode BASE64 ready response");
	return PS_AUTHFAIL;
    }

    des_ecb_encrypt((des_cblock *)buf2, (des_cblock *)buf2, schedule, 0);
    memcpy(challenge2.cstr, buf2, 4);
    if (ntohl(challenge2.cint) != challenge1.cint + 1) {
	error(0, -1, "challenge mismatch");
	return PS_AUTHFAIL;
    }	    

    memset(authenticator.dat, 0, sizeof authenticator.dat);

    result = htonl(challenge1.cint);
    memcpy(authenticator.dat, &result, sizeof result);

    /* The protection mechanisms and their corresponding bit-masks are as
     * follows:
     *
     * 1 No protection mechanism
     * 2 Integrity (krb_mk_safe) protection
     * 4 Privacy (krb_mk_priv) protection
     */
    authenticator.dat[4] = 1;

    len = strlen(tktuser);
    strncpy(authenticator.dat+8, tktuser, len);
    authenticator.length = len + 8 + 1;
    while (authenticator.length & 7) {
	authenticator.length++;
    }
    des_pcbc_encrypt((des_cblock *)authenticator.dat,
	    (des_cblock *)authenticator.dat, authenticator.length, schedule,
	    &session, 1);

    to64frombits(buf1, authenticator.dat, authenticator.length);
    if (outlevel == O_VERBOSE) {
	error(0, 0, "IMAP> %s", buf1);
    }
    SockWrite(sock, buf1, strlen(buf1));
    SockWrite(sock, "\r\n", 2);

    if (result = gen_recv(sock, buf1, sizeof buf1))
	return result;

    if (strstr(buf1, "OK")) {
        return PS_SUCCESS;
    }
    else {
	return PS_AUTHFAIL;
    }
}
#endif /* KERBEROS_V4 */

#ifdef GSSAPI
#define GSSAUTH_P_NONE      1
#define GSSAUTH_P_INTEGRITY 2
#define GSSAUTH_P_PRIVACY   4

static int do_gssauth(int sock, char *hostname, char *username)
{
    gss_buffer_desc request_buf, send_token;
    gss_buffer_t sec_token;
    gss_name_t target_name;
    gss_ctx_id_t context;
    gss_OID mech_name;
    gss_qop_t quality;
    int cflags;
    OM_uint32 maj_stat, min_stat;
    char buf1[8192], buf2[8192], server_conf_flags;
    unsigned long buf_size;
    int result;

    /* first things first: get an imap ticket for host */
    sprintf(buf1, "imap@%s", hostname);
    request_buf.value = buf1;
    request_buf.length = strlen(buf1) + 1;
    maj_stat = gss_import_name(&min_stat, &request_buf, gss_nt_service_name,
        &target_name);
    if (maj_stat != GSS_S_COMPLETE) {
        error(0, -1, "Couldn't get service name for [%s]", buf1);
        return PS_AUTHFAIL;
    }
    else if (outlevel == O_VERBOSE) {
        maj_stat = gss_display_name(&min_stat, target_name, &request_buf,
            &mech_name);
        error(0, 0, "Using service name [%s]",request_buf.value);
        maj_stat = gss_release_buffer(&min_stat, &request_buf);
    }

    gen_send(sock, "AUTHENTICATE GSSAPI");

    /* upon receipt of the GSSAPI authentication request, server returns
     * null data ready response. */
    if (result = gen_recv(sock, buf1, sizeof buf1)) {
        return result;
    }

    /* now start the security context initialisation loop... */
    sec_token = GSS_C_NO_BUFFER;
    context = GSS_C_NO_CONTEXT;
    if (outlevel == O_VERBOSE)
        error(0,0,"Sending credentials");
    do {
        maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL, 
            &context, target_name, NULL, 0, 0, NULL, sec_token, NULL,
	    &send_token, &cflags, NULL);
        if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
            error(0, -1,"Error exchanging credentials");
            gss_release_name(&min_stat, &target_name);
            /* wake up server and await NO response */
            SockWrite(sock, "\r\n", 2);
            if (result = gen_recv(sock, buf1, sizeof buf1))
                return result;
            return PS_AUTHFAIL;
        }
        to64frombits(buf1, send_token.value, send_token.length);
        gss_release_buffer(&min_stat, &send_token);
        SockWrite(sock, buf1, strlen(buf1));
        SockWrite(sock, "\r\n", 2);
        if (outlevel == O_VERBOSE)
            error(0,0,"IMAP> %s", buf1);
        if (maj_stat == GSS_S_CONTINUE_NEEDED) {
	    if (result = gen_recv(sock, buf1, sizeof buf1)) {
	        gss_release_name(&min_stat, &target_name);
	        return result;
	    }
	    request_buf.length = from64tobits(buf2, buf1 + 2);
	    request_buf.value = buf2;
	    sec_token = &request_buf;
        }
    } while (maj_stat == GSS_S_CONTINUE_NEEDED);
    gss_release_name(&min_stat, &target_name);

    /* get security flags and buffer size */
    if (result = gen_recv(sock, buf1, sizeof buf1)) {
        return result;
    }
    request_buf.length = from64tobits(buf2, buf1 + 2);
    request_buf.value = buf2;

    maj_stat = gss_unwrap(&min_stat, context, &request_buf, &send_token,
        &cflags, &quality);
    if (maj_stat != GSS_S_COMPLETE) {
        error(0,-1,"Couldn't unwrap security level data");
        gss_release_buffer(&min_stat, &send_token);
        return PS_AUTHFAIL;
    }
    if (outlevel == O_VERBOSE)
        error(0,0,"Credential exchange complete");
    /* first octet is security levels supported. We want none, for now */
    server_conf_flags = ((char *)send_token.value)[0];
    if ( !(((char *)send_token.value)[0] & GSSAUTH_P_NONE) ) {
        error(0,-1,"Server requires integrity and/or privacy");
        gss_release_buffer(&min_stat, &send_token);
        return PS_AUTHFAIL;
    }
    ((char *)send_token.value)[0] = 0;
    buf_size = ntohl(*((long *)send_token.value));
    /* we don't care about buffer size if we don't wrap data */
    gss_release_buffer(&min_stat, &send_token);
    if (outlevel == O_VERBOSE) {
        error(0,0,"Unwrapped security level flags: %s%s%s",
            server_conf_flags & GSSAUTH_P_NONE ? "N" : "-",
            server_conf_flags & GSSAUTH_P_INTEGRITY ? "I" : "-",
            server_conf_flags & GSSAUTH_P_PRIVACY ? "C" : "-");
        error(0,0,"Maximum GSS token size is %ld",buf_size);
    }

    /* now respond in kind (hack!!!) */
    buf_size = htonl(buf_size); /* do as they do... only matters if we do enc */
    memcpy(buf1, &buf_size, 4);
    buf1[0] = GSSAUTH_P_NONE;
    strcpy(buf1+4, username); /* server decides if princ is user */
    request_buf.length = 4 + strlen(username) + 1;
    request_buf.value = buf1;
    maj_stat = gss_wrap(&min_stat, context, 0, GSS_C_QOP_DEFAULT, &request_buf,
        &cflags, &send_token);
    if (maj_stat != GSS_S_COMPLETE) {
        error(0,-1,"Error creating security level request");
        return PS_AUTHFAIL;
    }
    to64frombits(buf1, send_token.value, send_token.length);
    if (outlevel == O_VERBOSE) {
        error(0,0,"Requesting authorisation as %s", username);
        error(0,0,"IMAP> %s",buf1);
    }
    SockWrite(sock, buf1, strlen(buf1));
    SockWrite(sock, "\r\n", 2);

    /* we should be done. Get status and finish up */
    if (result = gen_recv(sock, buf1, sizeof buf1))
        return result;
    if (strstr(buf1, "OK")) {
        /* flush security context */
        if (outlevel == O_VERBOSE)
            error(0, 0, "Releasing GSS credentials");
        maj_stat = gss_delete_sec_context(&min_stat, &context, &send_token);
        if (maj_stat != GSS_S_COMPLETE) {
            error(0, -1, "Error releasing credentials");
            return PS_AUTHFAIL;
        }
        /* send_token may contain a notification to the server to flush
         * credentials. RFC 1731 doesn't specify what to do, and since this
         * support is only for authentication, we'll assume the server
         * knows enough to flush its own credentials */
        return PS_SUCCESS;
    }

    return PS_AUTHFAIL;
}	
#endif /* GSSAPI */

int imap_getauth(int sock, struct query *ctl, char *greeting)
/* apply for connection authorization */
{
    char capabilities[POPBUFSIZE+1];
    int ok = 0;

    /* probe to see if we're running IMAP4 and can use RFC822.PEEK */
    gen_send(sock, "CAPABILITY");
    if ((ok = gen_recv(sock, capabilities, sizeof(capabilities))))
	return(ok);
    if (strstr(capabilities, "BAD"))
    {
	imap_version = IMAP2;
	if (outlevel == O_VERBOSE)
	    error(0, 0, "Protocol identified as IMAP2 or IMAP2BIS");
    }
    /* UW-IMAP server 10.173 notifies in all caps */
    else if (strstr(capabilities, "IMAP4rev1") || strstr(capabilities, "IMAP4REV1"))
    {
	imap_version = IMAP4rev1;
	if (outlevel == O_VERBOSE)
	    error(0, 0, "Protocol identified as IMAP4 rev 1");
    }
    else
    {
	imap_version = IMAP4;
	if (outlevel == O_VERBOSE)
	    error(0, 0, "Protocol identified as IMAP4 rev 0");
    }

    /* eat the tail of the CAPABILITY response (if any) */
    if ((peek_capable = (imap_version >= IMAP4)))
    {
	char	scratchbuf[POPBUFSIZE];	/* don't clobber capabilities buffer */

	if ((ok = gen_recv(sock, scratchbuf, sizeof(scratchbuf))))
	    return(ok);
    }

#ifdef GSSAPI
    if (strstr(capabilities, "AUTH=GSSAPI"))
    {
        if (ctl->server.protocol == P_IMAP_GSS)
        {
            if (outlevel == O_VERBOSE)
                error(0, 0, "GSS authentication is supported");
            return do_gssauth(sock, ctl->server.truename, ctl->remotename);
        }
    }
    else if (ctl->server.protocol == P_IMAP_GSS)
    {
        error(0,-1, "Required GSS capability not supported by server");
        return(PS_AUTHFAIL);
    }
#endif /* GSSAPI */

#ifdef KERBEROS_V4
    if (strstr(capabilities, "AUTH=KERBEROS_V4"))
    {
	if (outlevel == O_VERBOSE)
	    error(0, 0, "KERBEROS_V4 authentication is supported");

	if (ctl->server.protocol == P_IMAP_K4)
	{
	    if ((ok = do_rfc1731(sock, ctl->server.truename)))
	    {
		if (outlevel == O_VERBOSE)
		    error(0, 0, "IMAP> *");
		SockWrite(sock, "*\r\n", 3);
	    }
	    
	    return(ok);
	}
	/* else fall through to ourdinary AUTH=LOGIN case */
    }
    else if (ctl->server.protocol == P_IMAP_K4)
    {
	error(0,-1, "Required KERBEROS_V4 capability not supported by server");
	return(PS_AUTHFAIL);
    }
#endif /* KERBEROS_V4 */

    /* try to get authorized in the ordinary (AUTH=LOGIN) way */
    ok = gen_transact(sock, "LOGIN %s \"%s\"", ctl->remotename, ctl->password);
    if (ok)
	return(ok);

    return(PS_SUCCESS);
}

static int imap_getrange(int sock, 
			 struct query *ctl, 
			 const char *folder, 
			 int *countp, int *newp)
/* get range of messages to be fetched */
{
    int ok;

    /* find out how many messages are waiting */
    recent = unseen = -1;

    if (pass > 1)
    {
	/* 
	 * We have to have an expunge here, otherwise the re-poll will
	 * infinite-loop picking up un-expunged message.
	 */
	ok = 0;
	if (deletions && ctl->expunge > 1)
	    ok = gen_transact(sock, "EXPUNGE");
#ifdef IMAP_UID	/* not used */
	if (!ok)
	    expunge_uids(ctl);
#endif /* IMAP_UID */
	count = -1;
	if (ok || gen_transact(sock, "NOOP"))
	{
	    error(0, 0, "re-poll failed");
	    return(ok);
	}
	else if (count == -1)	/* no EXISTS response to NOOP */
	{
	    count = recent = 0;
	    unseen = -1;
	}
    }
    else
    {
	if (!check_only)
	    ok = gen_transact(sock, "SELECT %s", folder ? folder : "INBOX");
	else
	    ok = gen_transact(sock, "EXAMINE %s", folder ? folder : "INBOX");
	if (ok != 0)
	{
	    error(0, 0, "mailbox selection failed");
	    return(ok);
	}
    }

    *countp = count;

    /*
     * Note: because IMAP has an is_old method, this number is used
     * only for the "X messages (Y unseen)" notification.  Accordingly
     * it doesn't matter much that it can be wrong (e.g. if we see an
     * UNSEEN response but not all messages above the first UNSEEN one
     * are likewise).
     */
    if (unseen >= 0)		/* optional, but better if we see it */
	*newp = count - unseen + 1;
    else if (recent >= 0)	/* mandatory */
	*newp = recent;
    else
	*newp = -1;		/* should never happen, RECENT is mandatory */ 

    expunged = 0;

    return(PS_SUCCESS);
}

static int imap_getsizes(int sock, int count, int *sizes)
/* capture the sizes of all messages */
{
    char buf [POPBUFSIZE+1];

    /*
     * Some servers (as in, PMDF5.1-9.1 under OpenVMS 6.1)
     * won't accept 1:1 as valid set syntax.  Some implementors
     * should be taken out and shot for excessive anality.
     */
    if (count == 1)
	gen_send(sock, "FETCH 1 RFC822.SIZE", count);
    else
	gen_send(sock, "FETCH 1:%d RFC822.SIZE", count);
    for (;;)
    {
	int num, size, ok;

	if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);
	if (strstr(buf, "OK"))
	    break;
	else if (sscanf(buf, "* %d FETCH (RFC822.SIZE %d)", &num, &size) == 2)
	    sizes[num - 1] = size;
    }

    return(PS_SUCCESS);
}

static int imap_is_old(int sock, struct query *ctl, int number)
/* is the given message old? */
{
    int ok;

    /* expunges change the fetch numbers */
    number -= expunged;

    if ((ok = gen_transact(sock, "FETCH %d FLAGS", number)) != 0)
	return(PS_ERROR);

    return(seen);
}

static int imap_fetch_headers(int sock, struct query *ctl,int number,int *lenp)
/* request headers of nth message */
{
    char buf [POPBUFSIZE+1];
    int	num;

    /* expunges change the fetch numbers */
    number -= expunged;

    /*
     * This is blessed by RFC 1176, RFC1730, RFC2060.
     * According to the RFCs, it should *not* set the \Seen flag.
     */
    gen_send(sock, "FETCH %d RFC822.HEADER", number);

    /* looking for FETCH response */
    do {
	int	ok;

	if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);
    } while
	(sscanf(buf+2, "%d FETCH (%*s {%d}", &num, lenp) != 2);

    if (num != number)
	return(PS_ERROR);
    else
	return(PS_SUCCESS);
}

static int imap_fetch_body(int sock, struct query *ctl, int number, int *lenp)
/* request body of nth message */
{
    char buf [POPBUFSIZE+1], *cp;
    int	num;

    /* expunges change the fetch numbers */
    number -= expunged;

    /*
     * If we're using IMAP4, we can fetch the message without setting its
     * seen flag.  This is good!  It means that if the protocol exchange
     * craps out during the message, it will still be marked `unseen' on
     * the server.
     *
     * However...*don't* do this if we're using keep to suppress deletion!
     * In that case, marking the seen flag is the only way to prevent the
     * message from being re-fetched on subsequent runs.
     */
    switch (imap_version)
    {
    case IMAP4rev1:	/* RFC 2060 */
	if (!ctl->keep)
	    gen_send(sock, "FETCH %d BODY.PEEK[TEXT]", number);
	else
	    gen_send(sock, "FETCH %d BODY[TEXT]", number);
	break;

    case IMAP4:		/* RFC 1730 */
	if (!ctl->keep)
	    gen_send(sock, "FETCH %d RFC822.TEXT.PEEK", number);
	else
	    gen_send(sock, "FETCH %d RFC822.TEXT", number);
	break;

    default:		/* RFC 1176 */
	gen_send(sock, "FETCH %d RFC822.TEXT", number);
	break;
    }

    /* looking for FETCH response */
    do {
	int	ok;

	if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);
    } while
	(sscanf(buf+2, "%d FETCH", &num) != 1);

    if (num != number)
	return(PS_ERROR);

    /* try to extract a length */
    if ((cp = strchr(buf, '{')))
	*lenp = atoi(cp + 1);
    else
	*lenp = 0;

    return(PS_SUCCESS);
}

static int imap_trail(int sock, struct query *ctl, int number)
/* discard tail of FETCH response after reading message text */
{
    /* expunges change the fetch numbers */
    /* number -= expunged; */

    for (;;)
    {
	char buf[POPBUFSIZE+1];
	int ok;

	if ((ok = gen_recv(sock, buf, sizeof(buf))))
	    return(ok);

	/* UW IMAP returns "OK FETCH", Cyrus returns "OK Completed" */
	if (strstr(buf, "OK"))
	    break;
    }

    return(PS_SUCCESS);
}

static int imap_delete(int sock, struct query *ctl, int number)
/* set delete flag for given message */
{
    int	ok;

    /* expunges change the fetch numbers */
    number -= expunged;

    /*
     * Use SILENT if possible as a minor throughput optimization.
     * Note: this has been dropped from IMAP4rev1.
     */
    if ((ok = gen_transact(sock,
			imap_version == IMAP4 
				? "STORE %d +FLAGS.SILENT (\\Deleted)"
				: "STORE %d +FLAGS (\\Deleted)", 
			number)))
	return(ok);
    else
	deletions++;

    /*
     * We do an expunge after ctl->expunge messages, rather than
     * just before quit, so that a line hit during a long session
     * won't result in lots of messages being fetched again during
     * the next session.
     */
    if (NUM_NONZERO(ctl->expunge) && (deletions % ctl->expunge) == 0)
    {
	if ((ok = gen_transact(sock, "EXPUNGE")))
	    return(ok);

#ifdef IMAP_UID	/* not used */
	expunge_uids(ctl);
#endif /* IMAP_UID */

	expunged = deletions;
	deletions = 0;
    }

    return(PS_SUCCESS);
}

static int imap_logout(int sock, struct query *ctl)
/* send logout command */
{
    /* if expunges after deletion have been suppressed, ship one now */
    if (NUM_SPECIFIED(ctl->expunge) && NUM_ZERO(ctl->expunge) && deletions)
    {
	int	ok;

	if ((ok = gen_transact(sock, "EXPUNGE")))
	    return(ok);

	expunged = deletions;
	deletions = 0;

#ifdef IMAP_UID	/* not used */
	expunge_uids(ctl);
#endif /* IMAP_UID */
    }

    return(gen_transact(sock, "LOGOUT"));
}

const static struct method imap =
{
    "IMAP",		/* Internet Message Access Protocol */
    143,		/* standard IMAP2bis/IMAP4 port */
    TRUE,		/* this is a tagged protocol */
    FALSE,		/* no message delimiter */
    imap_ok,		/* parse command response */
    imap_getauth,	/* get authorization */
    imap_getrange,	/* query range of messages */
    imap_getsizes,	/* get sizes of messages (used for --limit option */
    imap_is_old,	/* no UID check */
    imap_fetch_headers,	/* request given message headers */
    imap_fetch_body,	/* request given message body */
    imap_trail,		/* eat message trailer */
    imap_delete,	/* delete the message */
    imap_logout,	/* expunge and exit */
    TRUE,		/* yes, we can re-poll */
};

int doIMAP(struct query *ctl)
/* retrieve messages using IMAP Version 2bis or Version 4 */
{
    return(do_protocol(ctl, &imap));
}

/* imap.c ends here */
