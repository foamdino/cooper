/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_THREADS_H
#define COOPER_THREADS_H

#include <pthread.h>
#include <stdint.h>
#include <string.h>
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
typedef struct thread_cfg thread_cfg_t;
typedef struct deep_sz_cfg deep_sz_cfg_t;

typedef enum thread_workers_status thread_workers_status_e;

enum thread_workers_status
{
	EXPORT_RUNNING            = (1 << 0),
	MEM_SAMPLING_RUNNING      = (1 << 1),
	SHM_EXPORT_RUNNING        = (1 << 2),
	HEAP_STATS_RUNNING        = (1 << 3),
	CLASS_CACHE_RUNNING       = (1 << 4),
	CALL_STACK_RUNNNG         = (1 << 5),
	FLAMEGRAPH_EXPORT_RUNNING = (1 << 6),
	METHOD_EVENTS_RUNNING     = (1 << 7),
	OBJ_ALLOC_EVENTS_RUNNING  = (1 << 8)
};

struct stack_bucket
{
	char *stack_str; /**< semicolon-joined call stack */
	size_t count;
};

/**
 * Config for a background thread
 */
struct thread_cfg
{
	const char *name;
	thread_id_e id;
	void *(*thread_fn)(void *);
	thread_workers_status_e status;
};

struct deep_sz_cfg
{
	const char *pattern;
	uint32_t mult;
	uint64_t overhead_bytes;
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
void *obj_alloc_event_thread_func(void *arg);

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