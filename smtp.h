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

int SMTP_helo(FILE *sockfp,char *host);
int SMTP_from(FILE *sockfp,char *from);
int SMTP_rcpt(FILE *sockfp,char *to);
int SMTP_data(FILE *sockfp);
int SMTP_eom(FILE *sockfp);
int SMTP_quit(FILE *sockfp);
int SMTP_ok(FILE *sockfp,char *argbuf);
void SMTP_rset(FILE *sockfp);

#endif
