#ifndef FM_LOCK_H
#define FM_LOCK_H

/* lock.c: concurrency locking */
void fm_lock_setup(struct runctl *);
void fm_lock_assert(void);
void fm_lock_or_die(void);
void fm_lock_release(void);
int  fm_lock_state(void);
void fm_lock_dispose(void);

#endif
