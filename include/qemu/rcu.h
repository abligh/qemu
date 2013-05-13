#ifndef _URCU_QSBR_H
#define _URCU_QSBR_H

/*
 * urcu-qsbr.h
 *
 * Userspace RCU QSBR header.
 *
 * LGPL-compatible code should include this header with :
 *
 * #define _LGPL_SOURCE
 * #include <urcu.h>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * IBM's contributions to this file may be relicensed under LGPLv2 or later.
 */

#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

#include "qemu/compiler.h"
#include "qemu/rcu-pointer.h"
#include "qemu/thread.h"
#include "qemu/tls.h"
#include "qemu/queue.h"
#include "qemu/atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Important !
 *
 * Each thread containing read-side critical sections must be registered
 * with rcu_register_thread() before calling rcu_read_lock().
 * rcu_unregister_thread() should be called before the thread exits.
 */

#ifdef DEBUG_RCU
#define rcu_assert(args...)    assert(args)
#else
#define rcu_assert(args...)
#endif

#define RCU_GP_ONLINE     (1UL << 0)
#define RCU_GP_CTR        (1UL << 1)

/*
 * Global quiescent period counter with low-order bits unused.
 * Using a int rather than a char to eliminate false register dependencies
 * causing stalls on some architectures.
 */
extern unsigned long rcu_gp_ctr;

extern QemuEvent rcu_gp_event;

struct rcu_reader_data {
    /* Data used by both reader and synchronize_rcu() */
    unsigned long ctr;
    bool waiting;

    /* Data used for registry, protected by rcu_gp_lock */
    QLIST_ENTRY(rcu_reader_data) node;
};

DECLARE_TLS(struct rcu_reader_data, rcu_reader);

static inline void rcu_read_lock(void)
{
    rcu_assert(tls_get_rcu_reader()->ctr);
}

static inline void rcu_read_unlock(void)
{
    /* Ensure that the previous reads complete before starting those
     * in another critical section.
     */
    smp_rmb();
}

static inline void rcu_quiescent_state(void)
{
    struct rcu_reader_data *p_rcu_reader = tls_get_rcu_reader();

    /* Reuses smp_rmb() in the last rcu_read_unlock().  */
    unsigned ctr = atomic_read(&rcu_gp_ctr);
    atomic_xchg(&p_rcu_reader->ctr, ctr);
    if (atomic_read(&p_rcu_reader->waiting)) {
        atomic_set(&p_rcu_reader->waiting, false);
        qemu_event_set(&rcu_gp_event);
    }
}

static inline void rcu_thread_offline(void)
{
    struct rcu_reader_data *p_rcu_reader = tls_get_rcu_reader();

    atomic_xchg(&p_rcu_reader->ctr, 0);
    if (atomic_read(&p_rcu_reader->waiting)) {
        atomic_set(&p_rcu_reader->waiting, false);
        qemu_event_set(&rcu_gp_event);
    }
}

static inline void rcu_thread_online(void)
{
    rcu_quiescent_state();
}

extern void synchronize_rcu(void);

/*
 * Reader thread registration.
 */
extern void rcu_register_thread(void);
extern void rcu_unregister_thread(void);

struct rcu_head;
typedef void RCUCBFunc(struct rcu_head *head);

struct rcu_head {
    struct rcu_head *next;
    RCUCBFunc *func;
};

extern void call_rcu1(struct rcu_head *head, RCUCBFunc *func);

/* The operands of the minus operator must have the same type,
 * which must be the one that we specify in the cast.
 */
#define call_rcu(head, func, field)                                      \
    call_rcu1(({                                                         \
         char __attribute__((unused))                                    \
            offset_must_be_zero[-offsetof(typeof(*(head)), field)],      \
            func_type_invalid = (func) - (void (*)(typeof(head)))(func); \
         &(head)->field;                                                 \
      }),                                                                \
      (RCUCBFunc *)(func))

#ifdef __cplusplus
}
#endif

#endif /* _URCU_QSBR_H */
