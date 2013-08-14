/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "ui/console.h"
#include "qemu/thread.h"

#include "hw/hw.h"

#include "qemu/timer.h"
#ifdef CONFIG_POSIX
#include <pthread.h>
#endif

#ifdef CONFIG_PPOLL
#include <poll.h>
#endif

#ifdef CONFIG_PRCTL_PR_SET_TIMERSLACK
#include <sys/prctl.h>
#endif

/***********************************************************/
/* timers */

typedef struct QEMUClock {
    QLIST_HEAD(, QEMUTimerList) timerlists;

    NotifierList reset_notifiers;
    int64_t last;
    QemuMutex reset_lock;

    QEMUClockType type;
    bool enabled;
} QEMUClock;

QEMUTimerListGroup main_loop_tlg;
QEMUClock qemu_clocks[QEMU_CLOCK_MAX];

/* A QEMUTimerList is a list of timers attached to a clock. More
 * than one QEMUTimerList can be attached to each clock, for instance
 * used by different AioContexts / threads. Each clock also has
 * a list of the QEMUTimerLists associated with it, in order that
 * reenabling the clock can call all the notifiers.
 */

struct QEMUTimerList {
    QEMUClock *clock;
    QemuMutex active_timers_lock;
    QEMUTimer *active_timers;
    QLIST_ENTRY(QEMUTimerList) list;
    QEMUTimerListNotifyCB *notify_cb;
    void *notify_opaque;
};

/**
 * qemu_clock_ptr:
 * @type: type of clock
 *
 * Translate a clock type into a pointer to QEMUClock object.
 *
 * Returns: a pointer to the QEMUClock object
 */
static inline QEMUClock *qemu_clock_ptr(QEMUClockType type)
{
    return &qemu_clocks[type];
}

static bool timer_expired_ns(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_head && (timer_head->expire_time <= current_time);
}

QEMUTimerList *timerlist_new(QEMUClockType type,
                             QEMUTimerListNotifyCB *cb,
                             void *opaque)
{
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);

    timer_list = g_malloc0(sizeof(QEMUTimerList));
    timer_list->clock = clock;
    timer_list->notify_cb = cb;
    timer_list->notify_opaque = opaque;
    qemu_mutex_init(&timer_list->active_timers_lock);
    QLIST_INSERT_HEAD(&clock->timerlists, timer_list, list);
    return timer_list;
}

void timerlist_free(QEMUTimerList *timer_list)
{
    assert(!timerlist_has_timers(timer_list));
    if (timer_list->clock) {
        QLIST_REMOVE(timer_list, list);
    }
    qemu_mutex_destroy(&timer_list->active_timers_lock);
    g_free(timer_list);
}

static void qemu_clock_init(QEMUClockType type)
{
    QEMUClock *clock = qemu_clock_ptr(type);

    clock->type = type;
    clock->enabled = true;
    clock->last = INT64_MIN;
    QLIST_INIT(&clock->timerlists);
    notifier_list_init(&clock->reset_notifiers);
    qemu_mutex_init(&clock->reset_lock);
    main_loop_tlg.tl[type] = timerlist_new(type, NULL, NULL);
}

bool qemu_clock_use_for_deadline(QEMUClockType type)
{
    return !(use_icount && (type == QEMU_CLOCK_VIRTUAL));
}

void qemu_clock_notify(QEMUClockType type)
{
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);
    QLIST_FOREACH(timer_list, &clock->timerlists, list) {
        timerlist_notify(timer_list);
    }
}

void qemu_clock_enable(QEMUClockType type, bool enabled)
{
    QEMUClock *clock = qemu_clock_ptr(type);
    bool old = clock->enabled;
    clock->enabled = enabled;
    if (enabled && !old) {
        qemu_clock_notify(type);
    }
}

bool timerlist_has_timers(QEMUTimerList *timer_list)
{
    return !!timer_list->active_timers;
}

bool qemu_clock_has_timers(QEMUClockType type)
{
    return timerlist_has_timers(
        main_loop_tlg.tl[type]);
}

bool timerlist_expired(QEMUTimerList *timer_list)
{
    int64_t expire_time;

    qemu_mutex_lock(&timer_list->active_timers_lock);
    if (!timer_list->active_timers) {
        qemu_mutex_unlock(&timer_list->active_timers_lock);
        return false;
    }
    expire_time = timer_list->active_timers->expire_time;
    qemu_mutex_unlock(&timer_list->active_timers_lock);

    return expire_time < qemu_clock_get_ns(timer_list->clock->type);
}

bool qemu_clock_expired(QEMUClockType type)
{
    return timerlist_expired(
        main_loop_tlg.tl[type]);
}

/*
 * As above, but return -1 for no deadline, and do not cap to 2^32
 * as we know the result is always positive.
 */

int64_t timerlist_deadline_ns(QEMUTimerList *timer_list)
{
    int64_t delta;
    int64_t expire_time;

    if (!timer_list->clock->enabled) {
        return -1;
    }

    /* The active timers list may be modified before the caller uses our return
     * value but ->notify_cb() is called when the deadline changes.  Therefore
     * the caller should notice the change and there is no race condition.
     */
    qemu_mutex_lock(&timer_list->active_timers_lock);
    if (!timer_list->active_timers) {
        qemu_mutex_unlock(&timer_list->active_timers_lock);
        return -1;
    }
    expire_time = timer_list->active_timers->expire_time;
    qemu_mutex_unlock(&timer_list->active_timers_lock);

    delta = expire_time - qemu_clock_get_ns(timer_list->clock->type);

    if (delta <= 0) {
        return 0;
    }

    return delta;
}

/* Calculate the soonest deadline across all timerlists attached
 * to the clock. This is used for the icount timeout so we
 * ignore whether or not the clock should be used in deadline
 * calculations.
 */
int64_t qemu_clock_deadline_ns_all(QEMUClockType type)
{
    int64_t deadline = -1;
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);
    QLIST_FOREACH(timer_list, &clock->timerlists, list) {
        deadline = qemu_soonest_timeout(deadline,
                                        timerlist_deadline_ns(timer_list));
    }
    return deadline;
}

QEMUClockType timerlist_get_clock(QEMUTimerList *timer_list)
{
    return timer_list->clock->type;
}

QEMUTimerList *qemu_clock_get_main_loop_timerlist(QEMUClockType type)
{
    return main_loop_tlg.tl[type];
}

void timerlist_notify(QEMUTimerList *timer_list)
{
    if (timer_list->notify_cb) {
        timer_list->notify_cb(timer_list->notify_opaque);
    } else {
        qemu_notify_event();
    }
}

/* Transition function to convert a nanosecond timeout to ms
 * This is used where a system does not support ppoll
 */
int qemu_timeout_ns_to_ms(int64_t ns)
{
    int64_t ms;
    if (ns < 0) {
        return -1;
    }

    if (!ns) {
        return 0;
    }

    /* Always round up, because it's better to wait too long than to wait too
     * little and effectively busy-wait
     */
    ms = (ns + SCALE_MS - 1) / SCALE_MS;

    /* To avoid overflow problems, limit this to 2^31, i.e. approx 25 days */
    if (ms > (int64_t) INT32_MAX) {
        ms = INT32_MAX;
    }

    return (int) ms;
}


/* qemu implementation of g_poll which uses a nanosecond timeout but is
 * otherwise identical to g_poll
 */
int qemu_poll_ns(GPollFD *fds, uint nfds, int64_t timeout)
{
#ifdef CONFIG_PPOLL
    if (timeout < 0) {
        return ppoll((struct pollfd *)fds, nfds, NULL, NULL);
    } else {
        struct timespec ts;
        ts.tv_sec = timeout / 1000000000LL;
        ts.tv_nsec = timeout % 1000000000LL;
        return ppoll((struct pollfd *)fds, nfds, &ts, NULL);
    }
#else
    return g_poll(fds, nfds, qemu_timeout_ns_to_ms(timeout));
#endif
}


void timer_init(QEMUTimer *ts,
                QEMUTimerList *timer_list, int scale,
                QEMUTimerCB *cb, void *opaque)
{
    ts->timer_list = timer_list;
    ts->cb = cb;
    ts->opaque = opaque;
    ts->scale = scale;
}

void timer_free(QEMUTimer *ts)
{
    g_free(ts);
}

/* stop a timer, but do not dealloc it */
void timer_del(QEMUTimer *ts)
{
    QEMUTimerList *timer_list = ts->timer_list;
    QEMUTimer **pt, *t;

    qemu_mutex_lock(&timer_list->active_timers_lock);
    pt = &timer_list->active_timers;
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            *pt = t->next;
            break;
        }
        pt = &t->next;
    }
    qemu_mutex_unlock(&timer_list->active_timers_lock);
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void timer_mod_ns(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimerList *timer_list = ts->timer_list;
    QEMUTimer **pt, *t;

    timer_del(ts);

    /* add the timer in the sorted list */
    qemu_mutex_lock(&timer_list->active_timers_lock);
    pt = &timer_list->active_timers;
    for(;;) {
        t = *pt;
        if (!timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }
    ts->expire_time = expire_time;
    ts->next = *pt;
    *pt = ts;
    qemu_mutex_unlock(&timer_list->active_timers_lock);

    /* Rearm if necessary  */
    if (pt == &timer_list->active_timers) {
        /* Interrupt execution to force deadline recalculation.  */
        qemu_clock_warp(timer_list->clock->type);
        timerlist_notify(timer_list);
    }
}

void timer_mod(QEMUTimer *ts, int64_t expire_time)
{
    timer_mod_ns(ts, expire_time * ts->scale);
}

bool timer_pending(QEMUTimer *ts)
{
    QEMUTimerList *timer_list = ts->timer_list;
    QEMUTimer *t;
    bool found = false;

    qemu_mutex_lock(&timer_list->active_timers_lock);
    for (t = timer_list->active_timers; t != NULL; t = t->next) {
        if (t == ts) {
            found = true;
            break;
        }
    }
    qemu_mutex_unlock(&timer_list->active_timers_lock);
    return found;
}

bool timer_expired(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_expired_ns(timer_head, current_time * timer_head->scale);
}

bool timerlist_run_timers(QEMUTimerList *timer_list)
{
    QEMUTimer *ts;
    int64_t current_time;
    bool progress = false;
   
    if (!timer_list->clock->enabled) {
        return progress;
    }

    current_time = qemu_clock_get_ns(timer_list->clock->type);
    for(;;) {
        qemu_mutex_lock(&timer_list->active_timers_lock);
        ts = timer_list->active_timers;
        if (!timer_expired_ns(ts, current_time)) {
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            break;
        }
        /* remove timer from the list before calling the callback */
        timer_list->active_timers = ts->next;
        ts->next = NULL;
        qemu_mutex_unlock(&timer_list->active_timers_lock);

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
        progress = true;
    }
    return progress;
}

bool qemu_clock_run_timers(QEMUClockType type)
{
    return timerlist_run_timers(main_loop_tlg.tl[type]);
}

void timerlistgroup_init(QEMUTimerListGroup *tlg,
                         QEMUTimerListNotifyCB *cb, void *opaque)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        tlg->tl[type] = timerlist_new(type, cb, opaque);
    }
}

void timerlistgroup_deinit(QEMUTimerListGroup *tlg)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        timerlist_free(tlg->tl[type]);
    }
}

bool timerlistgroup_run_timers(QEMUTimerListGroup *tlg)
{
    QEMUClockType type;
    bool progress = false;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        progress |= timerlist_run_timers(tlg->tl[type]);
    }
    return progress;
}

int64_t timerlistgroup_deadline_ns(QEMUTimerListGroup *tlg)
{
    int64_t deadline = -1;
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        if (qemu_clock_use_for_deadline(tlg->tl[type]->clock->type)) {
            deadline = qemu_soonest_timeout(deadline,
                                            timerlist_deadline_ns(
                                                tlg->tl[type]));
        }
    }
    return deadline;
}

int64_t qemu_clock_get_ns(QEMUClockType type)
{
    int64_t now, last;
    QEMUClock *clock = qemu_clock_ptr(type);

    switch (type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        if (use_icount) {
            return cpu_get_icount();
        } else {
            return cpu_get_clock();
        }
    case QEMU_CLOCK_HOST:
        qemu_mutex_lock(&clock->reset_lock);
        now = get_clock_realtime();
        last = clock->last;
        clock->last = now;
        qemu_mutex_unlock(&clock->reset_lock);
        if (now < last) {
            notifier_list_notify(&clock->reset_notifiers, &now);
        }
        return now;
    }
}

int64_t qemu_clock_get_ns_nobql(QEMUClockType type)
{
    int64_t now, last;
    QEMUClock *clock = qemu_clock_ptr(type);

    switch(type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        abort();
    case QEMU_CLOCK_HOST:
        qemu_mutex_lock(&clock->reset_lock);
        now = get_clock_realtime();
        last = clock->last;
        clock->last = now;
        qemu_mutex_unlock(&clock->reset_lock);
        if (now < last) {
            /* FIXME: trigger notification over iothread (and under BQL)
            notifier_list_notify(&clock->reset_notifiers, &now); */
        }
        return now;
    }
}

void qemu_clock_register_reset_notifier(QEMUClockType type,
                                        Notifier *notifier)
{
    QEMUClock *clock = qemu_clock_ptr(type);
    notifier_list_add(&clock->reset_notifiers, notifier);
}

void qemu_clock_unregister_reset_notifier(QEMUClockType type,
                                          Notifier *notifier)
{
    notifier_remove(notifier);
}

void init_clocks(void)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        qemu_clock_init(type);
    }

#ifdef CONFIG_PRCTL_PR_SET_TIMERSLACK
    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
#endif
}

uint64_t timer_expire_time_ns(QEMUTimer *ts)
{
    return timer_pending(ts) ? ts->expire_time : -1;
}

bool qemu_clock_run_all_timers(void)
{
    bool progress = false;
    QEMUClockType type;

    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        progress |= qemu_clock_run_timers(type);
    }

    return progress;
}
