/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_THREAD_WORKERS_H
#define COOPER_THREAD_WORKERS_H

#include "../lib/proc_mem.h"
#include "cooper_thread_manager.h"

#define MAX_BUCKETS   16384
#define ROLL_INTERVAL (1 * 60 * 1000000000ULL) //(10 * 60 * 1000000000ULL)

typedef struct stack_bucket stack_bucket_t;
struct stack_bucket
{
	char *stack_str; /**< semicolon-joined call stack */
	size_t count;
};

/* Main worker thread functions */
void *export_thread_func(void *arg);
void *mem_sampling_thread_func(void *arg);
void *heap_stats_thread_func(void *arg);
void *shm_export_thread_func(void *arg);
void *class_cache_thread_func(void *arg);
void *call_stack_sampling_thread_func(void *arg);
void *flamegraph_export_thread(void *arg);

/* Export functions that might be called from elsewhere */
void export_to_file(agent_context_t *ctx);

#endif /* COOPER_THREAD_WORKERS_H */