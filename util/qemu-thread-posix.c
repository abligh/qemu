/*
 * Wrappers around mutex/cond/thread functions
 *
 * Copyright Red Hat, Inc. 2009
 *
 * Author:
 *  Marcelo Tosatti <mtosatti@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef __linux__
#include <sys/syscall.h>
#include <linux/futex.h>
#endif
#include "qemu/thread.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"

#define BROKEN_CONDVAR_WITH_PI_MUTEX 1

#define PTHREAD_MUTEX_UNLOCKED  NULL
#define PTHREAD_MUTEX_LOCKED    (void *)1UL

static int rt_sched_policy;
static int max_sched_priority;
static bool resources_created;

static void error_exit(int err, const char *msg)
{
    fprintf(stderr, "qemu: %s: %s\n", msg, strerror(err));
    abort();
}

void qemu_realtime_init(int policy, int max_priority)
{
    assert(!resources_created);
    rt_sched_policy = policy;
    max_sched_priority = max_priority;
}

bool qemu_realtime_is_enabled(void)
{
    return rt_sched_policy != SCHED_OTHER;
}

void qemu_mutex_init(QemuMutex *mutex)
{
    int protocol = PTHREAD_PRIO_NONE;
    pthread_mutexattr_t mutexattr;
    int err;

    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
    if (rt_sched_policy != SCHED_OTHER) {
#ifdef BROKEN_CONDVAR_WITH_PI_MUTEX
        protocol = PTHREAD_PRIO_PROTECT;
        err = pthread_mutexattr_setprioceiling(&mutexattr, max_sched_priority);
        if (err) {
            error_exit(err, __func__);
        }
#else
        protocol = PTHREAD_PRIO_INHERIT;
#endif
    }
    err = pthread_mutexattr_setprotocol(&mutexattr, protocol);
    if (err) {
        error_exit(err, __func__);
    }
    err = pthread_mutex_init(&mutex->lock, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);
    if (err)
        error_exit(err, __func__);
    err = pthread_key_create(&mutex->locked, NULL);
    if (err)
        error_exit(err, __func__);
    resources_created = true;
}

void qemu_mutex_destroy(QemuMutex *mutex)
{
    int err;

    err = pthread_mutex_destroy(&mutex->lock);
    if (err)
        error_exit(err, __func__);
    err = pthread_key_delete(mutex->locked);
    if (err)
        error_exit(err, __func__);
}

void qemu_mutex_lock(QemuMutex *mutex)
{
    int err;

    err = pthread_mutex_lock(&mutex->lock);
    if (err)
        error_exit(err, __func__);
    pthread_setspecific(mutex->locked, PTHREAD_MUTEX_LOCKED);
}

int qemu_mutex_trylock(QemuMutex *mutex)
{
    int err;

    err = pthread_mutex_trylock(&mutex->lock);
    if (!err)
        pthread_setspecific(mutex->locked, PTHREAD_MUTEX_LOCKED);
    return err;
}

void qemu_mutex_unlock(QemuMutex *mutex)
{
    int err;

    pthread_setspecific(mutex->locked, PTHREAD_MUTEX_UNLOCKED);
    err = pthread_mutex_unlock(&mutex->lock);
    if (err)
        error_exit(err, __func__);
}

bool qemu_mutex_is_locked(QemuMutex *mutex)
{
    return pthread_getspecific(mutex->locked) == PTHREAD_MUTEX_LOCKED;
}

void qemu_cond_init(QemuCond *cond)
{
    int err;

    err = pthread_cond_init(&cond->cond, NULL);
    if (err)
        error_exit(err, __func__);
}

void qemu_cond_destroy(QemuCond *cond)
{
    int err;

    err = pthread_cond_destroy(&cond->cond);
    if (err)
        error_exit(err, __func__);
    resources_created = true;
}

void qemu_cond_signal(QemuCond *cond)
{
    int err;

    err = pthread_cond_signal(&cond->cond);
    if (err)
        error_exit(err, __func__);
}

void qemu_cond_broadcast(QemuCond *cond)
{
    int err;

    err = pthread_cond_broadcast(&cond->cond);
    if (err)
        error_exit(err, __func__);
}

void qemu_cond_wait(QemuCond *cond, QemuMutex *mutex)
{
    int err;

    rcu_thread_offline();
    pthread_setspecific(mutex->locked, PTHREAD_MUTEX_UNLOCKED);
    err = pthread_cond_wait(&cond->cond, &mutex->lock);
    rcu_thread_online();
    if (err)
        error_exit(err, __func__);
    pthread_setspecific(mutex->locked, PTHREAD_MUTEX_LOCKED);
}

void qemu_sem_init(QemuSemaphore *sem, int init)
{
    int rc;

#if defined(__APPLE__) || defined(__NetBSD__)
    rc = pthread_mutex_init(&sem->lock, NULL);
    if (rc != 0) {
        error_exit(rc, __func__);
    }
    rc = pthread_cond_init(&sem->cond, NULL);
    if (rc != 0) {
        error_exit(rc, __func__);
    }
    if (init < 0) {
        error_exit(EINVAL, __func__);
    }
    sem->count = init;
#else
    rc = sem_init(&sem->sem, 0, init);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif
}

void qemu_sem_destroy(QemuSemaphore *sem)
{
    int rc;

#if defined(__APPLE__) || defined(__NetBSD__)
    rc = pthread_cond_destroy(&sem->cond);
    if (rc < 0) {
        error_exit(rc, __func__);
    }
    rc = pthread_mutex_destroy(&sem->lock);
    if (rc < 0) {
        error_exit(rc, __func__);
    }
#else
    rc = sem_destroy(&sem->sem);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif
}

void qemu_sem_post(QemuSemaphore *sem)
{
    int rc;

#if defined(__APPLE__) || defined(__NetBSD__)
    pthread_mutex_lock(&sem->lock);
    if (sem->count == INT_MAX) {
        rc = EINVAL;
    } else if (sem->count++ < 0) {
        rc = pthread_cond_signal(&sem->cond);
    } else {
        rc = 0;
    }
    pthread_mutex_unlock(&sem->lock);
    if (rc != 0) {
        error_exit(rc, __func__);
    }
#else
    rc = sem_post(&sem->sem);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif
}

static void compute_abs_deadline(struct timespec *ts, int ms)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts->tv_nsec = tv.tv_usec * 1000 + (ms % 1000) * 1000000;
    ts->tv_sec = tv.tv_sec + ms / 1000;
    if (ts->tv_nsec >= 1000000000) {
        ts->tv_sec++;
        ts->tv_nsec -= 1000000000;
    }
}

int qemu_sem_timedwait(QemuSemaphore *sem, int ms)
{
    int rc;
    struct timespec ts;

    if (ms) {
        rcu_thread_offline();
    }

#if defined(__APPLE__) || defined(__NetBSD__)
    compute_abs_deadline(&ts, ms);
    pthread_mutex_lock(&sem->lock);
    --sem->count;
    while (sem->count < 0) {
        rc = pthread_cond_timedwait(&sem->cond, &sem->lock, &ts);
        if (rc == ETIMEDOUT) {
            ++sem->count;
            break;
        }
        if (rc != 0) {
            error_exit(rc, __func__);
        }
    }
    pthread_mutex_unlock(&sem->lock);
    if (rc == ETIMEDOUT) {
        rc == -1;
    }

#else
    if (ms <= 0) {
        /* This is cheaper than sem_timedwait.  */
        do {
            rc = sem_trywait(&sem->sem);
        } while (rc == -1 && errno == EINTR);
        if (rc == -1 && errno == EAGAIN) {
            goto out;
        }
    } else {
        compute_abs_deadline(&ts, ms);
        do {
            rc = sem_timedwait(&sem->sem, &ts);
        } while (rc == -1 && errno == EINTR);
        if (rc == -1 && errno == ETIMEDOUT) {
            goto out;
        }
    }
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif

out:
    if (ms) {
        rcu_thread_online();
    }
    return rc;
}

void qemu_sem_wait(QemuSemaphore *sem)
{
    rcu_thread_offline();

#if defined(__APPLE__) || defined(__NetBSD__)
    pthread_mutex_lock(&sem->lock);
    --sem->count;
    while (sem->count < 0) {
        pthread_cond_wait(&sem->cond, &sem->lock);
    }
    pthread_mutex_unlock(&sem->lock);
#else
    int rc;

    do {
        rc = sem_wait(&sem->sem);
    } while (rc == -1 && errno == EINTR);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif

    rcu_thread_online();
}

#ifdef __linux__
#define futex(...)              syscall(__NR_futex, __VA_ARGS__)

static inline void futex_wake(QemuEvent *ev, int n)
{
    futex(ev, FUTEX_WAKE, n, NULL, NULL, 0);
}

static inline void futex_wait(QemuEvent *ev, unsigned val)
{
    futex(ev, FUTEX_WAIT, (int) val, NULL, NULL, 0);
}
#else
static inline void futex_wake(QemuEvent *ev, int n)
{
    if (n == 1) {
        pthread_cond_signal(&ev->cond);
    } else {
        pthread_cond_broadcast(&ev->cond);
    }
}

static inline void futex_wait(QemuEvent *ev, unsigned val)
{
    pthread_mutex_lock(&ev->lock);
    if (ev->value == val) {
        pthread_cond_wait(&ev->cond, &ev->lock);
    }
    pthread_mutex_unlock(&ev->lock);
}
#endif

/* Valid transitions:
 * - free->set, when setting the event
 * - busy->set, when setting the event, followed by futex_wake
 * - set->free, when resetting the event
 * - free->busy, when waiting
 *
 * set->busy does not happen (it can be observed from the outside but
 * it really is set->free->busy).
 *
 * busy->free provably cannot happen; to enforce it, the set->free transition
 * is done with an OR, which becomes a no-op if the event has concurrently
 * transitioned to free or busy.
 */

#define EV_SET         0
#define EV_FREE        1
#define EV_BUSY       -1

void qemu_event_init(QemuEvent *ev, bool init)
{
#ifndef __linux__
    pthread_mutex_init(&ev->lock, NULL);
    pthread_cond_init(&ev->cond, NULL);
#endif

    ev->value = (init ? EV_SET : EV_FREE);
}

void qemu_event_destroy(QemuEvent *ev)
{
#ifndef __linux__
    pthread_mutex_destroy(&ev->lock);
    pthread_cond_destroy(&ev->cond);
#endif
}

void qemu_event_set(QemuEvent *ev)
{
    if (atomic_mb_read(&ev->value) != EV_SET) {
        if (atomic_xchg(&ev->value, EV_SET) == EV_BUSY) {
            /* There were waiters, wake them up.  */
            futex_wake(ev, INT_MAX);
        }
    }
}

void qemu_event_reset(QemuEvent *ev)
{
    if (atomic_mb_read(&ev->value) == EV_SET) {
        /*
         * If there was a concurrent reset (or even reset+wait),
         * do nothing.  Otherwise change EV_SET->EV_FREE.
         */
        atomic_or(&ev->value, EV_FREE);
    }
}

void qemu_event_wait(QemuEvent *ev)
{
    unsigned value;

    value = atomic_mb_read(&ev->value);
    if (value != EV_SET) {
        if (value == EV_FREE) {
            /*
             * Leave the event reset and tell qemu_event_set that there
             * are waiters.  No need to retry, because there cannot be
             * a concurent busy->free transition.  After the CAS, the
             * event will be either set or busy.
             */
            if (atomic_cmpxchg(&ev->value, EV_FREE, EV_BUSY) == EV_SET) {
                return;
            }
        }
        rcu_thread_offline();
        futex_wait(ev, EV_BUSY);
        rcu_thread_online();
    } else {
        rcu_quiescent_state();
    }
}


typedef struct QemuThreadData {
    /* Passed to win32_start_routine.  */
    void             *(*start_routine)(void *);
    void             *arg;
} QemuThreadData;

static void *thread_start_routine(void *arg)
{
    QemuThreadData *data = (QemuThreadData *) arg;
    void *(*start_routine)(void *) = data->start_routine;
    void *thread_arg = data->arg;
    void *ret;

    rcu_register_thread();
    g_free(data);
    ret = start_routine(thread_arg);
    rcu_unregister_thread();
    return ret;
}

void qemu_thread_create(QemuThread *thread,
                       void *(*start_routine)(void*),
                       void *arg, int flags)
{
    struct sched_param sched_param;
    sigset_t set, oldset;
    pthread_attr_t attr;
    QemuThreadData *data;
    int sched_policy;
    int err;

    data = g_malloc(sizeof(*data));
    data->start_routine = start_routine;
    data->arg = arg;

    err = pthread_attr_init(&attr);
    if (err) {
        error_exit(err, __func__);
    }
    if (flags & QEMU_THREAD_DETACHED) {
        err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (err) {
            error_exit(err, __func__);
        }
    }

    if (rt_sched_policy != SCHED_OTHER) {
        err = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        if (err) {
            error_exit(err, __func__);
        }
        if (flags & QEMU_THREAD_PRIO_MAX) {
            sched_policy = rt_sched_policy;
            sched_param.sched_priority = max_sched_priority;
        } else if (flags & QEMU_THREAD_PRIO_RT) {
            sched_policy = rt_sched_policy;
            sched_param.sched_priority = max_sched_priority - 1;
        } else {
#ifdef BROKEN_CONDVAR_WITH_PI_MUTEX
            sched_policy = SCHED_FIFO;
            sched_param.sched_priority = 1;
#else
            sched_policy = SCHED_OTHER;
            sched_param.sched_priority = 0;
#endif
        }
        err = pthread_attr_setschedpolicy(&attr, sched_policy);
        if (err) {
            error_exit(err, __func__);
        }
        err = pthread_attr_setschedparam(&attr, &sched_param);
        if (err) {
            error_exit(err, __func__);
        }
    }

    /* Leave signal handling to the iothread.  */
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
    err = pthread_create(&thread->thread, &attr, thread_start_routine, data);
    if (err)
        error_exit(err, __func__);

    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    pthread_attr_destroy(&attr);
    resources_created = true;
}

void qemu_thread_get_self(QemuThread *thread)
{
    thread->thread = pthread_self();
}

bool qemu_thread_is_self(QemuThread *thread)
{
   return pthread_equal(pthread_self(), thread->thread);
}

void qemu_thread_exit(void *retval)
{
    pthread_exit(retval);
}

void *qemu_thread_join(QemuThread *thread)
{
    int err;
    void *ret;

    err = pthread_join(thread->thread, &ret);
    if (err) {
        error_exit(err, __func__);
    }
    return ret;
}
