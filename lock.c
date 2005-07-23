/*
 * lock.c -- cross-platform concurrency locking for fetchmail
 *
 * For license terms, see the file COPYING in this directory.
 */
#include "config.h"

#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h> /* strcat() */
#endif
#if defined(STDC_HEADERS)
#include <stdlib.h>
#endif
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "fetchmail.h"
#include "i18n.h"

static char *lockfile;		/* name of lockfile */
static int lock_acquired;	/* have we acquired a lock */

void lock_setup(void)
/* set up the global lockfile name */
{
    /* set up to do lock protocol */
#define	FETCHMAIL_PIDFILE	"fetchmail.pid"
    if (getuid() == ROOT_UID) {
	lockfile = (char *)xmalloc(
		sizeof(PID_DIR) + sizeof(FETCHMAIL_PIDFILE) + 1);
	strcpy(lockfile, PID_DIR);
	strcat(lockfile, "/");
	strcat(lockfile, FETCHMAIL_PIDFILE);
    } else {
	lockfile = (char *)xmalloc(strlen(fmhome)+sizeof(FETCHMAIL_PIDFILE)+2);
	strcpy(lockfile, fmhome);
	strcat(lockfile, "/");
        if (fmhome == home)
 	   strcat(lockfile, ".");
	strcat(lockfile, FETCHMAIL_PIDFILE);
    }
#undef FETCHMAIL_PIDFILE
}

#ifdef HAVE_ON_EXIT
static void unlockit(int n, void *p)
#else
static void unlockit(void)
#endif
/* must-do actions for exit (but we can't count on being able to do malloc) */
{
    if (lockfile && lock_acquired)
	unlink(lockfile);
}

void lock_dispose(void)
/* arrange for a lock to be removed on process exit */
{
#ifdef HAVE_ATEXIT
    atexit(unlockit);
#endif
#ifdef HAVE_ON_EXIT
    on_exit(unlockit, (char *)NULL);
#endif
}

int lock_state(void)
{
    int		pid, st;
    FILE	*lockfp;
    int		bkgd = FALSE;

    if ((lockfp = fopen(lockfile, "r")) != NULL)
    {
	int args = fscanf(lockfp, "%d %d", &pid, &st);
	bkgd = (args == 2);

	if (ferror(lockfp))
	    fprintf(stderr, GT_("fetchmail: error reading lockfile \"%s\": %s\n"),
		    lockfile, strerror(errno));

	if (args == 0 || kill(pid, 0) == -1) {
	    fprintf(stderr,GT_("fetchmail: removing stale lockfile\n"));
	    pid = 0;
	    if (unlink(lockfile))
		perror(lockfile);
	}
	fclose(lockfp); /* not checking should be safe, file mode was "r" */
    } else {
	pid = 0;
	if (errno != ENOENT)
	    fprintf(stderr, GT_("fetchmail: error opening lockfile \"%s\": %s\n"),
		    lockfile, strerror(errno));
    }

    return(bkgd ? -pid : pid);
}

void lock_assert(void)
/* assert that we already posess a lock */
{
    lock_acquired = TRUE;
}

void lock_or_die(void)
/* get a lock on a given host or exit */
{
    int fd;
    char	tmpbuf[50];

    if (!lock_acquired) {
	int e = 0;

	if ((fd = open(lockfile, O_WRONLY|O_CREAT|O_EXCL, 0666)) != -1) {
	    snprintf(tmpbuf, sizeof(tmpbuf), "%ld\n", (long)getpid());
	    if (write(fd, tmpbuf, strlen(tmpbuf)) < strlen(tmpbuf)) e = 1;
	    if (run.poll_interval)
	    {
		snprintf(tmpbuf, sizeof(tmpbuf), "%d\n", run.poll_interval);
		if (write(fd, tmpbuf, strlen(tmpbuf)) < strlen(tmpbuf)) e = 1;
	    }
	    if (fsync(fd)) e = 1;
	    if (close(fd)) e = 1;
	}
	if (e == 0) {
	    lock_acquired = TRUE;
	} else {
	    perror(lockfile);
	    fprintf(stderr, GT_("fetchmail: lock creation failed.\n"));
	    exit(PS_EXCLUDE);
	}
    }
}

void lock_release(void)
/* release a lock on a given host */
{
    unlink(lockfile);
}
/* lock.c ends here */
