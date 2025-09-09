/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_SHM_H
#define COOPER_SHM_H

#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "../lib/log.h"

#define COOPER_DATA_SHM_NAME     "/cooper_data"
#define COOPER_STATUS_SHM_NAME   "/cooper_status"
#define COOPER_SHM_VERSION       1
#define COOPER_MAX_ENTRIES       1024
#define COOPER_MAX_SIGNATURE_LEN 512

/* Calculate maximum data size for fixed union sizing */
#define COOPER_METHOD_DATA_SZ       sizeof(struct cooper_method_data)
#define COOPER_MEMORY_DATA_SZ       sizeof(struct cooper_memory_data)
#define COOPER_OBJECT_ALLOC_DATA_SZ sizeof(struct cooper_object_alloc_data)

#define COOPER_MAX_DATA_SZ                                                               \
	((COOPER_METHOD_DATA_SZ > COOPER_MEMORY_DATA_SZ)                                 \
	     ? ((COOPER_METHOD_DATA_SZ > COOPER_OBJECT_ALLOC_DATA_SZ)                    \
	            ? COOPER_METHOD_DATA_SZ                                              \
	            : COOPER_OBJECT_ALLOC_DATA_SZ)                                       \
	     : ((COOPER_MEMORY_DATA_SZ > COOPER_OBJECT_ALLOC_DATA_SZ)                    \
	            ? COOPER_MEMORY_DATA_SZ                                              \
	            : COOPER_OBJECT_ALLOC_DATA_SZ))

enum cooper_entry_status
{
	ENTRY_EMPTY = 0,
	ENTRY_READY = 1,
	ENTRY_READ  = 2
};

enum cooper_data_type
{
	COOPER_DATA_METHOD_METRIC = 1,
	COOPER_DATA_MEMORY_SAMPLE = 2,
	COOPER_DATA_OBJECT_ALLOC  = 3,
	COOPER_DATA_HEAP_STATS    = 4,
	COOPER_DATA_CLASS_STACKS  = 5
};

typedef enum cooper_entry_status cooper_entry_status_e;
typedef enum cooper_data_type cooper_data_type_e;

typedef struct cooper_method_data cooper_method_data_t;
typedef struct cooper_object_alloc_data cooper_object_alloc_data_t;
typedef struct cooper_memory_data cooper_memory_data_t;
typedef struct cooper_heap_stats_data cooper_heap_stats_data_t;
typedef struct cooper_sample_entry cooper_sample_entry_t;
typedef struct cooper_data_shm cooper_data_shm_t;
typedef struct cooper_status_shm cooper_status_shm_t;
typedef struct cooper_shm_context cooper_shm_context_t;

struct cooper_method_data
{
	char signature[COOPER_MAX_SIGNATURE_LEN];
	uint64_t call_count;
	uint64_t sample_count;
	uint64_t total_time_ns;
	uint64_t min_time_ns;
	uint64_t max_time_ns;
	uint64_t alloc_bytes;
	uint64_t peak_memory;
	uint64_t cpu_cycles;
	uint32_t metric_flags;
};

struct cooper_object_alloc_data
{
	char class_signature[COOPER_MAX_SIGNATURE_LEN];
	uint64_t allocation_count;
	uint64_t current_instances;
	uint64_t total_bytes;
	uint64_t peak_instances;
	uint64_t min_size;
	uint64_t max_size;
	uint64_t avg_size;
};

struct cooper_memory_data
{
	uint64_t process_memory;
	uint64_t thread_id;
	uint64_t thread_memory;
};

struct cooper_heap_stats_data
{
	char class_signature[COOPER_MAX_SIGNATURE_LEN];
	uint64_t instance_count;
	uint64_t total_sz;
	uint64_t total_deep_sz;
	uint64_t avg_sz;
	uint64_t avg_deep_sz;
};

struct cooper_sample_entry
{
	cooper_data_type_e type;
	uint64_t timestamp;
	union {
		cooper_method_data_t method;
		cooper_memory_data_t memory;
		cooper_object_alloc_data_t object_alloc;
		cooper_heap_stats_data_t heap_stats;
		char padding[COOPER_MAX_DATA_SZ];
	} data;
};

/* Agent writes here, CLI reads here */
struct cooper_data_shm
{
	uint32_t version;
	uint32_t max_entries;
	uint64_t start_time;
	uint32_t next_write_index; /* Agent maintains this */
	cooper_sample_entry_t entries[COOPER_MAX_ENTRIES];
};

/* CLI writes here, Agent reads here */
struct cooper_status_shm
{
	volatile uint32_t status[COOPER_MAX_ENTRIES];
};

/* Shared memory context for agent */
struct cooper_shm_context
{
	int data_fd;                     /* File descriptor for data shm */
	int status_fd;                   /* File descriptor for status shm */
	cooper_data_shm_t *data_shm;     /* Agent writes, CLI reads */
	cooper_status_shm_t *status_shm; /* CLI writes, Agent reads */
	size_t data_shm_size;
	size_t status_shm_size;
};

/* Function declarations */
int cooper_shm_init_agent(cooper_shm_context_t *ctx);
int cooper_shm_cleanup_agent(cooper_shm_context_t *ctx);
int cooper_shm_write_data(cooper_shm_context_t *ctx, unsigned int type, void *data);

void cooper_shm_cleanup_read_entries(cooper_shm_context_t *ctx);

#endif /* COOPER_SHM_H */