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

#ifdef HAVE_PROTOTYPES
int SMTP_helo(int socket,char *host);
int SMTP_from(int socket,char *from);
int SMTP_rcpt(int socket,char *to);
int SMTP_data(int socket);
int SMTP_eom(int socket);
int SMTP_quit(int socket);
int SMTP_ok(int socket,char *argbuf);
void SMTP_rset(int socket);
#endif /* HAVE_PROTOTYPES */

#endif
