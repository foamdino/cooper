/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_THREADS_H
#define COOPER_THREADS_H

#include <pthread.h>
#include <stdint.h>
// #include <errno.h>

#include "cooper.h"
#include "cooper_shm.h"
#include "cooper_ring.h"

#include "../lib/log.h"
#include "../lib/thread_util.h"
#include "../lib/proc_mem.h"

#define MAX_HASH_SIZE 20000
#define MAX_BUCKETS   16384
#define ROLL_INTERVAL (1 * 60 * 1000000000ULL) //(10 * 60 * 1000000000ULL)

typedef struct stack_bucket stack_bucket_t;
struct stack_bucket
{
	char *stack_str; /**< semicolon-joined call stack */
	size_t count;
};

/* Simple thread management functions */
int start_all_threads(agent_context_t *ctx);
void stop_all_threads(agent_context_t *ctx);

/* Main worker thread functions */
void *export_thread_func(void *arg);
void *mem_sampling_thread_func(void *arg);
void *heap_stats_thread_func(void *arg);
void *shm_export_thread_func(void *arg);
void *class_cache_thread_func(void *arg);
void *call_stack_sampling_thread_func(void *arg);
void *flamegraph_export_thread(void *arg);
void *method_event_thread_func(void *arg);

/* Set a specific worker status bit */
static inline void
set_worker_status(unsigned int *status, unsigned int flag)
{
	*status |= flag;
}

/* Check if a specific worker status bit is set - returns non-zero if set, zero if not set
 */
static inline int
check_worker_status(unsigned int status, unsigned int flag)
{
	return status & flag;
}

/* Clear a specific worker status bit */
static inline void
clear_worker_status(unsigned int *status, unsigned int flag)
{
	*status &= ~flag;
}

#endif /* COOPER_THREADS_H */