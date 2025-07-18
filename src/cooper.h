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

#include <sys/mman.h>
#include <sys/syscall.h>

#include "arena.h"
#include "arena_str.h"
#include "log.h"
#include "cpu.h"
#include "cache.h"
#include "config.h"
#include "shared_mem.h"
#include "thread_util.h"
#include "heap.h"

/* Macro to tag callback function params that we don't use */
#define UNUSED(x) (void)(x)

#define DEFAULT_CFG_FILE "trace.ini"
#define MAX_SIG_SZ 1024 /**< The max size of a class/method sig we are willing to tolerate */
#define MAX_THREAD_MAPPINGS 1024
#define MAX_MEMORY_SAMPLES 100 /**< The max number of memory samples to keep */
#define MAX_OBJECT_TYPES 2048 /**< The max types of objects to track */

/* Arena Sizes - Amount of memory to be allocated by each arena */
#define EXCEPTION_ARENA_SZ 1024 * 1024
#define LOG_ARENA_SZ 1024 * 1024
#define SAMPLE_ARENA_SZ 2048 * 1024
#define CONFIG_ARENA_SZ 512 * 1024
#define METRICS_ARENA_SZ 8 * 1024 * 1024
#define CACHE_ARENA_SZ 12 * 1024 * 1024
#define SCRATCH_ARENA_SZ 2 * 1024 * 1024
#define HEAP_STATS_ARENA_SZ 512 * 1024

/* Arena Counts - Amount of blocks for each arena */
#define EXCEPTION_ARENA_BLOCKS 1024
#define LOG_ARENA_BLOCKS 1024
#define EVENT_ARENA_BLOCKS 1024
#define SAMPLE_ARENA_BLOCKS 1024
#define CONFIG_ARENA_BLOCKS 1024
#define METRICS_ARENA_BLOCKS 1024
#define CACHE_ARENA_BLOCKS 1024
#define HEAP_STATS_ARENA_BLOCKS 1024
#define SCRATCH_ARENA_BLOCKS 1024

/* Arena Names */
#define EXCEPTION_ARENA_NAME "exception_arena"
#define LOG_ARENA_NAME "log_arena"
#define SAMPLE_ARENA_NAME "sample_arena"
#define CONFIG_ARENA_NAME "config_arena"
#define METRICS_ARENA_NAME "metrics_arena"
#define CACHE_ARENA_NAME "cache_arena"
#define HEAP_STATS_ARENA_NAME "heap_stats_arena"
#define SCRATCH_ARENA_NAME "scratch_arena"


/* Metric flags for method sampling */
#define METRIC_FLAG_TIME    0x0001
#define METRIC_FLAG_MEMORY  0x0002
#define METRIC_FLAG_CPU     0x0004

/* Ok/Err */
#define COOPER_OK 0
#define COOPER_ERR 1

/* Method cache */
#define METHOD_CACHE_NAME "method_cache"
#define METHOD_CACHE_MAX_ENTRIES 256

/* Class cache */
#define CLASS_CACHE_NAME "class_sig_cache"
#define CLASS_CACHE_MAX_ENTRIES 128


typedef struct trace_event trace_event_t;
typedef struct method_stats method_stats_t;
typedef struct config config_t;
typedef struct method_sample method_sample_t;
typedef struct class_stats class_stats_t;
typedef struct method_cache_key method_cache_key_t;
typedef struct method_cache_value method_cache_value_t;
typedef struct thread_context thread_context_t;
typedef struct method_metrics_soa method_metrics_soa_t;
typedef struct app_memory_metrics app_memory_metrics_t;
typedef struct thread_memory_metrics thread_memory_metrics_t;
typedef struct agent_context agent_context_t;
typedef struct thread_alloc thread_alloc_t;
typedef struct thread_id_mapping thread_id_mapping_t;
typedef struct memory_metrics_mgr memory_metrics_mgr_t;
typedef struct object_allocation_metrics object_allocation_metrics_t;
typedef struct heap_iteration_context heap_iteration_context_t;

typedef struct class_cache_key class_cache_key_t;
typedef struct class_cache_value class_cache_value_t;
typedef struct class_entry class_entry_t;
typedef struct class_hash_table class_hash_table_t;
typedef struct class_info class_info_t;

typedef void *thread_fn(void *args);

/**
 * Struct-of-Arrays for storing method metrics
 * 
 * This structure organizes metrics in a columnar format for better
 * cache locality and more efficient data processing.
 */
struct method_metrics_soa 
{
    size_t capacity;          /**< Total capacity allocated */
    size_t count;             /**< Current number of methods being tracked */
    
    /* Identification data */
    char **signatures;        /**< Array of method signatures */
    int *sample_rates;        /**< Configured sample rate for each method */
    
    /* Counters */
    uint64_t *call_counts;    /**< Number of times each method has been called */
    uint64_t *sample_counts;  /**< Number of times each method has been sampled */
    
    /* Timing metrics */
    uint64_t *total_time_ns;  /**< Total execution time in nanoseconds */
    uint64_t *min_time_ns;    /**< Minimum execution time */
    uint64_t *max_time_ns;    /**< Maximum execution time */
    
    /* Memory metrics */
    uint64_t *alloc_bytes;    /**< Total bytes allocated */
    uint64_t *peak_memory;    /**< Peak memory usage */
    
    /* CPU metrics */
    uint64_t *cpu_cycles;     /**< CPU cycles used */
    
    /* Flags for which metrics are collected for each method */
    unsigned int *metric_flags;
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

    uint64_t *allocation_counts; /**< Number of instances allocated */
    uint64_t *total_bytes; /**< Total bytes allocated for this type */
    uint64_t *peak_instances; /**< Peak number of live instances */
    uint64_t *current_instances; /**< Current live instances */

    uint64_t *min_size; /**< Min object size seen */
    uint64_t *max_size; /**< Max object size seen */
    uint64_t *avg_size; /**< Avg object size seen */
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
    int method_index;       /**< Index in the metrics arrays, -1 if not sampling */
    jmethodID method_id; /**< ID of method assigned by jvm */
    uint64_t start_time;    /**< Starting timestamp in nanoseconds */
    uint64_t start_stack_depth; /**< Starting stack depth */
    uint64_t current_alloc_bytes; /**< Running total of allocations during method */
    uint64_t start_cpu;     /**< Starting CPU cycle count */
    method_sample_t *parent; /**< Parent (or calling) method */
};

struct method_cache_key 
{
    jmethodID method_id;
};

struct class_stats 
{
    char* class_name;
    uint64_t instance_count;
    uint64_t total_size;
    uint64_t avg_size;
};

struct heap_iteration_context 
{
    JNIEnv* env;
    jvmtiEnv* jvmti;
    arena_t* arena;
    class_hash_table_t *class_table;
};

struct method_cache_value 
{
    char class_signature[MAX_SIG_SZ];
    char method_name[64];
    char method_signature[256];
    int should_sample;
};

struct class_cache_key 
{
    jclass class_ref;           /* Class reference as key */
};

struct class_cache_value 
{
    char class_signature[MAX_SIG_SZ];
    int valid;                  /* Validation flag */
};

struct thread_context
{
    int stack_depth; /**< Depth of call stack */
    method_sample_t *sample; /**< Current top of method sample stack - most recent call */
};

struct class_info
{
    char class_sig[MAX_SIG_SZ];
    uint8_t in_heap_iteration;
};

/* Pre-allocate hash table for class stats during setup */
struct class_entry
{
    char class_sig[MAX_SIG_SZ];
    class_stats_t stats;
    uint8_t occupied; /* 0=empty, 1=occupied */
};

struct class_hash_table 
{
    class_entry_t *entries;
    size_t capacity;
    size_t count;
};

struct thread_alloc
{
    jlong thread_id; /**< Java thread ID */
    uint64_t total_allocated; /**< Total bytes allocated */
    uint64_t current_live_bytes; /**< Current live allocation */
    thread_alloc_t *next; /**< Pointer to next thread alloc in list */
};

struct thread_id_mapping
{
    jlong java_thread_id; /**< Java thread id from Thread.getId() */
    pid_t native_thread_id; /**< Native thread id from Linux: gettid */
};

struct config
{
    int rate;
    char **filters;
    int num_filters;
    char *sample_file_path;
    char *export_method; /**< only support file for now */
    int mem_sample_interval; /**< Interval between taking mem samples */
    int export_interval; /**< export to file every 60 seconds */
};

struct agent_context
{
    int event_counter;              /**< Counter for nth samples */
    jvmtiEnv *jvmti_env;            /**< JVMTI environment */
    JavaVM *jvm;                    /**< JVM itself */
    jclass java_thread_class;       /**< Global reference for java.lang.Thread class */
    jmethodID getId_method;         /**< Cached Thread.getId() method ID */
    char **method_filters;          /**< Method filter list */
    int num_filters;                /**< Number of filters */
    FILE *log_file;                 /**< Log output file */
    pthread_t log_thread;           /**< Logging thread */
    pthread_t export_thread;        /**< Export thread */
    pthread_t mem_sampling_thread;  /**< Mem sampling background thread */
    pthread_t shm_export_thread;    /**< Export via shared mem thread */
    pthread_t heap_stats_thread;    /**< Heap stats background thread */
    pthread_mutex_t samples_lock;   /**< Lock for sample arrays */
    int export_running;             /**< Flag to signal if export thread should continue */
    int mem_sampling_running;       /**< Flag to signal if memory sampling thread should continue */
    int shm_export_running;         /**< Flag to signal if the export data via shared mem is running */
    int heap_stats_running;         /**< Flag to signal if the heap stats thread is running */
    cooper_shm_context_t *shm_ctx;  /**< Shared mem context */
    config_t config;                /**< Agent configuration */
    arena_node_t *arena_head;       /**< First arena in the list */
    arena_node_t *arena_tail;       /**< Last arena in the list */
    method_metrics_soa_t *metrics;  /**< Method metrics in SoA format */
    app_memory_metrics_t *app_memory_metrics; /**< App level metrics in SoA format */
    thread_memory_metrics_t *thread_mem_head; /**< Thread level metrics linked list */
    object_allocation_metrics_t *object_metrics; /**< Object allocation metrics in SoA format */
    thread_id_mapping_t thread_mappings[MAX_THREAD_MAPPINGS]; /**< Map between java thread and native thread */
    /* Heap statistics results */
    min_heap_t *last_heap_stats;
    size_t last_heap_stats_count;
    uint64_t last_heap_stats_time;
};

/* jmvti callback functions */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value);
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location);

/* Methods sampling functions */
int should_sample_method(agent_context_t *ctx, const char *class_signature, const char *method_name, const char *method_signature);
int load_config(agent_context_t *ctx, const char *cf);
void cleanup(agent_context_t *ctx);
int start_thread(pthread_t *thread, thread_fn *tf, char *name, agent_context_t *ctx);

/* Metrics management functions */
method_metrics_soa_t *init_method_metrics(arena_t *arena, size_t initial_capacity);
int add_method_to_metrics(agent_context_t *ctx, const char *signature, int sample_rate, unsigned int flags);
int find_method_index(method_metrics_soa_t *metrics, const char *signature);
void record_method_execution(agent_context_t *ctx, int method_index, uint64_t exec_time_ns, uint64_t memory_bytes, uint64_t cycles);

/* Export functions */
void export_to_file(agent_context_t *ctx);
void *export_thread_func(void *arg);

#endif /* COOPER_H */