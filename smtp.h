/*
 * smtp.h -- prototypes for smtp handling code
 *
 * For license terms, see the file COPYING in this directory.
 */

#ifndef _POPSMTP_
#define _POPSMTP_

#define         SMTPBUFSIZE     256

/* SMTP error values */
#define         SM_OK              0
#define         SM_ERROR           128
#define         SM_UNRECOVERABLE   129

/* ESMTP extension option masks (not all options are listed here) */
#define ESMTP_8BITMIME	0x01
#define ESMTP_SIZE	0x02

int SMTP_helo(FILE *sockfp,char *host);
int SMTP_ehlo(FILE *sockfp,char *host,int *opt);
int SMTP_from(FILE *sockfp,char *from,char *opts);
int SMTP_rcpt(FILE *sockfp,char *to);
int SMTP_data(FILE *sockfp);
int SMTP_eom(FILE *sockfp);
int SMTP_quit(FILE *sockfp);
int SMTP_ok(FILE *sockfp);

#endif
