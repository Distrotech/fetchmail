#include "fetchmail.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

using namespace std;

const char *program_name = "unmime";
int outlevel = 0;

#define BUFSIZE_INCREMENT 4096

#ifdef DEBUG
#define DBG_FWRITE(B,L,BS,FD) do { if (fwrite((B), (L), (BS), (FD))) { } } while(0)
#else
#define DBG_FWRITE(B,L,BS,FD)
#endif

int main(int argc, char *argv[])
{
  unsigned int BufSize;
  char *buffer, *buf_p;
  int nl_count, i, bodytype;

  /* quench warnings about unused arguments */
  (void)argc;
  (void)argv;

#ifdef DEBUG
  pid_t pid;
  FILE *fd_orig, *fd_conv;
  char fnam[100];
  char buf[BUFSIZ];

  /* we don't need snprintf here, but for consistency, we'll use it */
  pid = getpid();
  snprintf(fnam, sizeof(fnam), "/tmp/i_unmime.%lx", (long)pid);
  fd_orig = fopen(fnam, "w");
  snprintf(fnam, sizeof(fnam), "/tmp/o_unmime.%lx", (long)pid);
  fd_conv = fopen(fnam, "w");
#endif

  BufSize = BUFSIZE_INCREMENT;    /* Initial size of buffer */
  buf_p = buffer = (char *) xmalloc(BufSize);
  nl_count = 0;

  do {
    i = fread(buf_p, 1, 1, stdin);
    switch (*buf_p) {
     case '\n':
       nl_count++;
       break;

     case '\r':
       break;

     default:
       nl_count = 0;
       break;
    }

    buf_p++;
    if ((unsigned)(buf_p - buffer) == BufSize) {
       /* Buffer is full! Get more room. */
       buffer = (char *)xrealloc(buffer, BufSize+BUFSIZE_INCREMENT);
       buf_p = buffer + BufSize;
       BufSize += BUFSIZE_INCREMENT;
    }
  } while ((i > 0) && (nl_count < 2));

  *buf_p = '\0';
  DBG_FWRITE(buffer, strlen(buffer), 1, fd_orig);

  UnMimeHeader(buffer);
  bodytype = MimeBodyType(buffer, 1);

  i = strlen(buffer);
  DBG_FWRITE(buffer, i, 1, fd_conv);
  if (fwrite(buffer, i, 1, stdout) < 1) {
      perror("fwrite");
      goto barf;
  }
  
  do {
     buf_p = (buffer - 1);
     do {
        buf_p++;
        i = fread(buf_p, 1, 1, stdin);
     } while ((i == 1) && (*buf_p != '\n'));
     if (i == 1) buf_p++;
     *buf_p = '\0';
     DBG_FWRITE(buf, (buf_p - buffer), 1, fd_orig);

     if (buf_p > buffer) {
        if (bodytype & MSG_NEEDS_DECODE) {
           buf_p = buffer;
           UnMimeBodyline(&buf_p, 0, 0);
        }
        DBG_FWRITE(buffer, (buf_p - buffer), 1, fd_conv);
        if (fwrite(buffer, (buf_p - buffer), 1, stdout) < 1) {
	    perror("fwrite");
	    goto barf;
	}
     }
  } while (buf_p > buffer);

barf:
  free(buffer);
  if (EOF == fflush(stdout)) perror("fflush");

#ifdef DEBUG
  fclose(fd_orig);
  fclose(fd_conv);
#endif

  return 0;
}
