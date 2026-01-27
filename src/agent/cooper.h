/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_H
#define COOPER_H

#include <jvmti.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <inttypes.h>
#include <stdatomic.h>

#include <sys/mman.h>
#include <sys/syscall.h>

/* library includes */
#include "../lib/arena.h"
#include "../lib/arena_str.h"
#include "../lib/log.h"
#include "../lib/cpu.h"
#include "../lib/thread_util.h"
#include "../lib/heap.h"
#include "../lib/ht.h"
#include "../lib/ring/ring_channel.h"
#include "../lib/jvm/class.h"
#include "../lib/jvm/injection.h"

/* agent includes */
#include "cooper_types.h"
#include "config.h"
#include "cooper_shm.h"

/* Macro to tag callback function params that we don't use */
#define UNUSED(x)        (void)(x)

#define DEFAULT_CFG_FILE "trace.ini"
#define MAX_SIG_SZ                                                                       \
	1024 /**< The max size of a class/method sig we are willing to tolerate */
#define MAX_THREAD_MAPPINGS 1024
#define MAX_MEMORY_SAMPLES  100  /**< The max number of memory samples to keep */
#define MAX_OBJECT_TYPES    2048 /**< The max types of objects to track */
#define CALL_STACK_CHANNEL_CAPACITY                                                      \
	4096                      /**< The max num of elements in the ring channel */
#define LOG_RING_CAPACITY    1024 /**< Max number of log messages in ring */
#define METHOD_RING_CAPACITY 4096 /**< Max number of method events in ring */
#define MAX_METHOD_EVENT_SZ  512  /**< Max size of a method event message */
#define CLASS_RING_CAPACITY  1024 /**< Max number of class events in ring */
#define MAX_CLASS_EVENT_SZ   1024 /**< Max size of a class event message */

/* Arena Sizes - Amount of memory to be allocated by each arena */
#define LOG_ARENA_SZ         1024 * 1024

#define CONFIG_ARENA_SZ      512 * 1024
#define METRICS_ARENA_SZ     8 * 1024 * 1024
#define SCRATCH_ARENA_SZ     16 * 1024 * 1024
#define CLASS_CACHE_ARENA_SZ 12 * 1024 * 1024
#define FLAMEGRAPH_ARENA_SZ  1024 * 1024
#define BYTECODE_ARENA_SZ    8 * 1024 * 1024

/* Arena Names */
#define LOG_ARENA_NAME         "log_arena"

#define CONFIG_ARENA_NAME      "config_arena"
#define METRICS_ARENA_NAME     "metrics_arena"
#define CLASS_CACHE_ARENA_NAME "class_cache_arena"
#define SCRATCH_ARENA_NAME     "scratch_arena"
#define FLAMEGRAPH_ARENA_NAME  "flamegraph_arena"
#define BYTECODE_ARENA_NAME    "bytecode_arena"

/* Ok/Err */
#define COOPER_OK        0
#define COOPER_ERR       1

#define MAX_STACK_FRAMES 64

typedef struct package_filter package_filter_t;
typedef struct config config_t;
typedef struct method_sample method_sample_t;
typedef struct object_ref_info object_ref_info_t;
typedef struct call_stack_sample call_stack_sample_t;
typedef struct class_stats class_stats_t;
typedef struct thread_context thread_context_t;
typedef struct method_metrics_soa method_metrics_soa_t;
typedef struct app_memory_metrics app_memory_metrics_t;
typedef struct thread_memory_metrics thread_memory_metrics_t;
typedef struct thread_manager_ctx thread_manager_ctx_t;
typedef struct agent_context agent_context_t;
typedef struct thread_alloc thread_alloc_t;
typedef struct thread_id_mapping thread_id_mapping_t;
typedef struct object_allocation_metrics object_allocation_metrics_t;
typedef struct heap_iteration_context heap_iteration_context_t;
typedef struct callbacks callbacks_t;

typedef struct cooper_method_info cooper_method_info_t;
typedef struct cooper_class_info cooper_class_info_t;

typedef enum thread_id thread_id_e;

enum arenas
{
	LOG_ARENA_ID,
	CONFIG_ARENA_ID,
	METRICS_ARENA_ID,
	SCRATCH_ARENA_ID,
	CLASS_CACHE_ARENA_ID,
	FLAMEGRAPH_ARENA_ID,
	BYTECODE_ARENA_ID,
	ARENA_ID__LAST
};

enum thread_id
{
	THREAD_ID_EXPORT,
	THREAD_ID_MEM_SAMPLING,
	THREAD_ID_HEAP_STATS,
	THREAD_ID_SHM_EXPORT,
	THREAD_ID_CLASS_CACHE,
	THREAD_ID_CALL_STACK,
	THREAD_ID_FLAMEGRAPH,
	THREAD_ID_METHOD_EVENTS,
	THREAD_ID__COUNT
};

struct call_stack_sample
{
	uint64_t timestamp_ns;              /**< sample time */
	jlong thread_id;                    /**< Java thread ID */
	size_t frame_count;                 /**< number of captured frames */
	jmethodID frames[MAX_STACK_FRAMES]; /**< top-of-stack first */
};

/**
 * Struct-of-Arrays for storing method metrics
 *
 * This structure organizes metrics in a columnar format for better
 * cache locality and more efficient data processing.
 */
struct method_metrics_soa
{
	size_t capacity; /**< Total capacity allocated */
	size_t count;    /**< Current number of methods being tracked */

	/* Identification data */
	char **signatures; /**< Array of method signatures */
	int *sample_rates; /**< Configured sample rate for each method */

	/* Flags for which metrics are collected for each method */
	unsigned int *metric_flags;

	/* Counters */
	_Atomic(uint64_t)
	    *call_counts; /**< Number of times each method has been called */
	// uint64_t *sample_counts; /**< Number of times each method has been sampled */

	/* Timing metrics */
	_Atomic(uint64_t) *total_time_ns; /**< Total execution time in nanoseconds */
	_Atomic(uint64_t) *min_time_ns;   /**< Minimum execution time */
	_Atomic(uint64_t) *max_time_ns;   /**< Maximum execution time */

	/* Memory metrics */
	_Atomic(uint64_t) *alloc_bytes; /**< Total bytes allocated */
	_Atomic(uint64_t) *peak_memory; /**< Peak memory usage */

	/* CPU metrics */
	_Atomic(uint64_t) *cpu_cycles; /**< CPU cycles used */

	_Atomic(uint64_t) *call_sample_counts; /**< Call stack sample counts */
};

struct app_memory_metrics
{
	uint64_t process_memory_sample[MAX_MEMORY_SAMPLES];
	uint64_t timestamps[MAX_MEMORY_SAMPLES];
	size_t sample_count;
	pthread_mutex_t lock;
};

struct thread_memory_metrics
{
	jlong thread_id;
	uint64_t memory_samples[MAX_MEMORY_SAMPLES];
	uint64_t timestamps[MAX_MEMORY_SAMPLES];
	size_t sample_count;
	thread_memory_metrics_t *next;
};

struct object_allocation_metrics
{
	size_t capacity;
	size_t count;

	char **class_signatures; /**< Array of class signatures */

	_Atomic(uint64_t) *allocation_counts; /**< Number of instances allocated */
	_Atomic(uint64_t) *total_bytes;       /**< Total bytes allocated for this type */
	_Atomic(uint64_t) *peak_instances;    /**< Peak number of live instances */
	_Atomic(uint64_t) *current_instances; /**< Current live instances */

	_Atomic(uint64_t) *min_size; /**< Min object size seen */
	_Atomic(uint64_t) *max_size; /**< Max object size seen */
	_Atomic(uint64_t) *avg_size; /**< Avg object size seen */
};

/**
 * Thread-local storage for tracking method execution
 *
 * While our JVM agent itself only runs a few dedicated threads (main, event processing,
 * logging, etc.), the JVMTI callbacks (method_entry_callback and method_exit_callback)
 * are executed in the context of the Java application threads that are running the
 * methods we're monitoring.
 *
 * This is a critical design consideration: when we receive these callbacks, we're
 * actually running in the thread that's executing the Java method. Since multiple
 * Java threads can simultaneously execute different methods that we're monitoring,
 * we need per-thread state to track each method's execution independently.
 *
 * For example:
 * 1. Java Thread A enters method foo() → we store its start time
 * 2. Java Thread B enters method bar() → we store its start time
 * 3. Thread A exits foo() → we need Thread A's original start time to calculate duration
 * 4. Thread B exits bar() → we need Thread B's original start time to calculate duration
 *
 * Without thread-local storage, we would have a single global structure that would
 * get overwritten by each thread, leading to incorrect timing measurements.
 *
 * The thread-local sample structure stores:
 * - The method index being monitored in this thread
 * - The starting timestamp when the method was entered
 * - Starting values for any metrics we want to measure (memory, CPU, etc.)
 *
 * When the method exits, we retrieve this thread's sample data to calculate
 * the differences for metrics recording.
 */
struct method_sample
{
	int method_index;    /**< Index in the metrics arrays, -1 if not sampling */
	jmethodID method_id; /**< ID of method assigned by jvm */
	uint64_t start_time; /**< Starting timestamp in nanoseconds */
	uint64_t start_stack_depth;   /**< Starting stack depth */
	uint64_t current_alloc_bytes; /**< Running total of allocations during method */
	uint64_t start_cpu;           /**< Starting CPU cycle count */
};

struct object_ref_info
{
	jlong object_tag;         /* Tag we assign to track this object */
	jlong class_tag;          /* Class tag from your existing system */
	uint64_t shallow_size;    /* Object's own size */
	uint64_t deep_size;       /* Calculated deep size */
	int deep_size_calculated; /* Flag to avoid recalculation */
};

struct class_stats
{
	char *class_name;
	uint64_t instance_count;
	uint64_t total_size;
	uint64_t total_deep_size;
	uint64_t avg_size;
	uint64_t avg_deep_size;
};

struct heap_iteration_context
{
	JNIEnv *env;
	jvmtiEnv *jvmti;
	arena_t *arena;
	hashtable_t *class_table;
};

struct callbacks
{
	jvmtiEventCallbacks event_callbacks;
	jvmtiHeapCallbacks heap_callbacks;
};

struct thread_context
{
	int stack_depth;                           /**< Depth of call stack */
	method_sample_t samples[MAX_STACK_FRAMES]; /**< Fixed array of samples */
};

struct cooper_method_info
{
	jmethodID method_id;
	char *method_name;
	char *method_signature;
	int sample_index; /**< -1 for not sampled, index into SoA structure */
	char *full_name;
};

struct cooper_class_info
{
	jclass global_ref; /**< GlobalRef to the class, valid across threads */
	char class_sig[MAX_SIG_SZ];
	uint8_t in_heap_iteration;
	uint32_t method_count;
	cooper_method_info_t *methods; /**< Array of methods for this class */
};

struct thread_alloc
{
	jlong thread_id;             /**< Java thread ID */
	uint64_t total_allocated;    /**< Total bytes allocated */
	uint64_t current_live_bytes; /**< Current live allocation */
	thread_alloc_t *next;        /**< Pointer to next thread alloc in list */
};

struct thread_id_mapping
{
	jlong java_thread_id;   /**< Java thread id from Thread.getId() */
	pid_t native_thread_id; /**< Native thread id from Linux: gettid */
};

struct config
{
	int rate;                // TODO check if this is actually used
	char **filters;          // TODO check if this is actually used
	int num_filters;         // TODO check if this is actually used
	char *sample_file_path;  // TODO check if this is actually used
	char *export_method;     /**< only support file for now */
	int mem_sample_interval; /**< Interval between taking mem samples */
	int export_interval;     /**< export to file every 60 seconds */
};

struct thread_manager_ctx
{
	pthread_t threads[THREAD_ID__COUNT];
	unsigned int worker_statuses; /**< Bitfield flags for background worker threads -
	                                     see thread_workers_status */
	pthread_mutex_t samples_lock; /**< Lock for sample arrays */
};

struct agent_context
{
	int event_counter;        /**< Counter for nth samples */
	jvmtiEnv *jvmti_env;      /**< JVMTI environment */
	JavaVM *jvm;              /**< JVM itself */
	jclass java_thread_class; /**< Global reference for java.lang.Thread class */
	jmethodID getId_method;   /**< Cached Thread.getId() method ID */
	callbacks_t callbacks;    /**< Centralized callback structures */
	pattern_filter_t unified_filter;   /**< Unified filter from config */
	FILE *log_file;                    /**< Log output file */
	pthread_t log_thread;              /**< Logging thread */
	thread_manager_ctx_t tm_ctx;       /**< Holds state/threads for thread_manager */
	mpsc_ring_t log_ring;              /**< MPSC ring for logging */
	mpsc_ring_t method_ring;           /**< MPSC ring for method events */
	mpsc_ring_t class_ring;            /**< MPSC ring for class events */
	ring_channel_t call_stack_channel; /**< ring channel for call stacks */
	cooper_shm_context_t *shm_ctx;     /**< Shared mem context */
	config_t config;                   /**< Agent configuration */
	arena_t *arenas[ARENA_ID__LAST];   /**< Array of arenas */
	hashtable_t
	    *class_info_by_name; /**< Hashtable: class_sig -> cooper_class_info_t* */
	hashtable_t *interesting_methods; /**< Hashtable of methods we care about */
	method_metrics_soa_t *metrics;    /**< Method metrics in SoA format */
	app_memory_metrics_t *app_memory_metrics; /**< App level metrics in SoA format */
	thread_memory_metrics_t *thread_mem_head; /**< Thread level metrics linked list */
	object_allocation_metrics_t
	    *object_metrics; /**< Object allocation metrics in SoA format */
	thread_id_mapping_t
	    thread_mappings[MAX_THREAD_MAPPINGS]; /**< Map between java thread and native
	                                             thread */
	/* Heap statistics results */
	min_heap_t *last_heap_stats;
	size_t last_heap_stats_count;
	uint64_t last_heap_stats_time;
};

int load_config(agent_context_t *ctx, const char *cf);

pattern_filter_entry_t *find_matching_filter(const pattern_filter_t *filter,
                                             const char *class_sig,
                                             const char *method_name,
                                             const char *method_sig);

thread_context_t *get_thread_local_context();
method_sample_t *init_method_sample(arena_t *arena,
                                    int method_index,
                                    jmethodID method_id,
                                    uint64_t timestamp,
                                    uint64_t cpu);

/* Metrics management functions */
method_metrics_soa_t *init_method_metrics(arena_t *arena, size_t initial_capacity);
int add_method_to_metrics(agent_context_t *ctx,
                          const char *signature,
                          int sample_rate,
                          unsigned int flags);
int find_method_index(method_metrics_soa_t *metrics, const char *signature);

/* Export functions */
void export_to_file(agent_context_t *ctx);
void *export_thread_func(void *arg);

uint64_t get_current_time_ns();

/* djb2 hash function for strings */
static inline size_t
hash_string(const void *key, size_t capacity)
{
	assert(key != NULL);
	assert(capacity > 0);
	const char *str = (const char *)key;

	size_t hash = 5381;
	int c;
	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c;
	}
	return hash % capacity;
}

static inline int
cmp_string(const void *a, const void *b)
{
	return strcmp((const char *)a, (const char *)b);
}

/* Hash function for jmethodID (pointer) */
static inline size_t
hash_jmethodid(const void *key, size_t capacity)
{
	uintptr_t addr = (uintptr_t)key;

	/* Mix the bits for better distribution */
	addr ^= addr >> 16;
	addr ^= addr >> 8;
	addr *= 0x9e3779b9; /* Golden ratio approximation */

	return addr % capacity;
}

/* Compare function for jmethodID */
static inline int
cmp_jmethodid(const void *a, const void *b)
{
	/* Direct pointer comparison */
	if (a == b)
		return 0;
	return (a < b) ? -1 : 1;
}

#endif /* COOPER_H */