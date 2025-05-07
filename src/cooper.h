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
#include <sys/mman.h>
#include <sys/syscall.h>


#include <time.h>

#include "arena.h"

#define DEFAULT_CFG_FILE "trace.ini"
#define MAX_STR_LEN 4096 /**< Max length of string we want to care about */
#define EVENT_Q_SZ 2048 /**< An event q buffer */
#define FULL_SAMPLE_SZ 1024 /**< The max entries for the every sample buffer */
#define NTH_SAMPLE_SZ 256 /**< The max entries for the nth sample buffer */
#define MAX_SIG_SZ 1024 /**< The max size of a class/method sig we are willing to tolerate */
#define MAX_LOG_MSG_SZ 1024 /**< The max size of a trace message we will tolerate */
#define LOG_Q_SZ 1024 /**< Length of log q */
#define LOG(ctx, fmt, ...) do { \
    char msg[MAX_LOG_MSG_SZ]; \
    int len = snprintf(msg, sizeof(msg), "[JMVTI] " fmt, ##__VA_ARGS__); \
    if (len >= 0 && len < MAX_LOG_MSG_SZ) { \
        log_enq(ctx, msg); \
    } \
} while (0)
#define MAX_THREAD_MAPPINGS 1024

/* Arena Sizes - Amount of memory to be allocated by each arena */
#define EXCEPTION_ARENA_SZ 1024 * 1024
#define LOG_ARENA_SZ 1024 * 1024
#define EVENT_ARENA_SZ 2048 * 1024
#define SAMPLE_ARENA_SZ 2048 * 1024
#define CONFIG_ARENA_SZ 512 * 1024
#define METRICS_ARENA_SZ 8 * 1024 * 1024

/* Arena Counts - Amount of blocks for each arena */
#define EXCEPTION_ARENA_BLOCKS 1024
#define LOG_ARENA_BLOCKS 1024
#define EVENT_ARENA_BLOCKS 1024
#define SAMPLE_ARENA_BLOCKS 1024
#define CONFIG_ARENA_BLOCKS 1024
#define METRICS_ARENA_BLOCKS 1024

/* Metric flags for method sampling */
#define METRIC_FLAG_TIME    0x0001
#define METRIC_FLAG_MEMORY  0x0002
#define METRIC_FLAG_CPU     0x0004

typedef struct log_q log_q_t;
typedef struct trace_event trace_event_t;
typedef struct event_q event_q_t;
typedef struct method_stats method_stats_t;
typedef struct config config_t;
typedef struct method_sample method_sample_t;
typedef struct thread_context thread_context_t;
typedef struct method_metrics_soa method_metrics_soa_t;
typedef struct agent_context agent_context_t;
typedef struct thread_alloc thread_alloc_t;
typedef struct thread_id_mapping thread_id_mapping_t;
typedef struct memory_metrics_mgr memory_metrics_mgr_t;
typedef void *thread_fn(void *args);


/**
 * Struct-of-Arrays for storing method metrics
 * 
 * This structure organizes metrics in a columnar format for better
 * cache locality and more efficient data processing.
 */
struct method_metrics_soa {
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
    uint64_t start_process_memory;  /**< Starting memory usage in bytes */
    uint64_t start_thread_memory; /**< Starting thread specific memory */
    uint64_t start_stack_depth; /**< Starting stack depth */
    uint64_t current_alloc_bytes; /**< Running total of allocations during method */
    uint64_t start_cpu;     /**< Starting CPU cycle count */
    method_sample_t *parent; /**< Parent (or calling) method */
};

struct thread_context
{
    int stack_depth; /**< Depth of call stack */
    method_sample_t sample;
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
    int export_interval; /**< export to file every 60 seconds */
};

struct log_q
{
    char *messages[LOG_Q_SZ];
    int hd;
    int tl;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
};

struct agent_context
{
    int event_counter;              /**< Counter for nth samples */
    // method_stats_t full_samples[FULL_SAMPLE_SZ]; /**< Full event samples */
    // int full_hd;                    /**< Head index for full samples */
    // int full_count;                 /**< Number of full samples */
    // method_stats_t nth_samples[NTH_SAMPLE_SZ];   /**< Nth event samples */
    // int nth_hd;                     /**< Head index for nth samples */
    // int nth_count;                  /**< Number of nth samples */
    jvmtiEnv *jvmti_env;            /**< JVMTI environment */
    char **method_filters;          /**< Method filter list */
    int num_filters;                /**< Number of filters */
    log_q_t log_queue;              /**< Logging queue */
    FILE *log_file;                 /**< Log output file */
    pthread_t log_thread;           /**< Logging thread */
    pthread_t export_thread;        /**< Export thread */
    pthread_mutex_t samples_lock;   /**< Lock for sample arrays */
    int export_running;             /**< Flag to signal if export thread should continue */
    config_t config;                /**< Agent configuration */
    arena_node_t *arena_head;       /**< First arena in the list */
    arena_node_t *arena_tail;       /**< Last arena in the list */
    method_metrics_soa_t *metrics;  /**< Method metrics in SoA format */
    thread_id_mapping_t thread_mappings[MAX_THREAD_MAPPINGS]; /**< Map between java thread and native thread */
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

/* Logging system functions */
int init_log_q(agent_context_t *ctx);
void log_enq(agent_context_t *ctx, const char *msg);
char *log_deq(agent_context_t *ctx);
void *log_thread_func(void *arg);
void cleanup_log_system(agent_context_t *ctx);

/* Sample management functions */
void init_samples(agent_context_t *ctx);
void cleanup_samples(agent_context_t *ctx);

/* Export functions */
void export_to_file(agent_context_t *ctx);
void *export_thread_func(void *arg);

/**
 * String utility functions for configuration parsing
 * 
 * These functions provide safe string manipulation operations for
 * configuration parsing, with clear ownership semantics and arena-based
 * memory management.
 */

/**
 * Strip trailing comment from a string using arena allocation
 * Preserves '#' characters inside quoted strings
 * 
 * @param arena     Pointer to the arena
 * @param str       String to process
 * @return          Newly allocated string without comments, or NULL on error
 */
static char *arena_strip_comment(arena_t *arena, const char *str)
{
    assert(arena != NULL);
    assert(str != NULL);
    
    if (!arena || !str)
        return NULL;
    
    /* Find the comment marker, but ignore '#' inside quotes */
    const char *p = str;
    const char *comment = NULL;
    int in_quotes = 0;
    
    while (*p) {
        if (*p == '"') {
            in_quotes = !in_quotes; /* Toggle quote state */
        } else if (*p == '#' && !in_quotes) {
            comment = p;
            break;
        }
        p++;
    }
    
    size_t len;
    if (comment) {
        len = comment - str;
    } else {
        len = strlen(str);
    }
    
    /* Allocate and copy the substring */
    char *result = arena_alloc(arena, len + 1);
    if (!result)
        return NULL;
    
    memcpy(result, str, len);
    result[len] = '\0';
    
    return result;
}

/**
 * Trim whitespace from a string using arena allocation
 * 
 * @param arena     Pointer to the arena
 * @param str       String to trim
 * @return          Newly allocated trimmed string, or NULL on error
 */
static char *arena_trim(arena_t *arena, const char *str)
{
    assert(arena != NULL);
    assert(str != NULL);
    
    if (!arena || !str)
        return NULL;
    
    /* Skip leading whitespace */
    while (isspace((unsigned char)*str))
        str++;
    
    /* All whitespace or empty string */
    if (*str == '\0') {
        char *result = arena_alloc(arena, 1);
        if (result)
            *result = '\0';
        return result;
    }
    
    /* Find the end of the string */
    size_t len = strlen(str);
    const char *end = str + len - 1;
    
    /* Move backward to find the last non-whitespace character */
    while (end > str && isspace((unsigned char)*end))
        end--;
    
    /* Calculate the trimmed length */
    size_t trimmed_len = end - str + 1;
    
    /* Allocate and copy the trimmed string */
    char *result = arena_alloc(arena, trimmed_len + 1);
    if (!result)
        return NULL;
    
    memcpy(result, str, trimmed_len);
    result[trimmed_len] = '\0';
    
    return result;
}

/**
 * Extract value part from a "key = value" string and trim it, using arena allocation
 * Also handles quoted values by removing surrounding quotes
 * 
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Extracted and trimmed value, or NULL if no value found or on error
 */
static char *arena_extract_and_trim_value(arena_t *arena, const char *line)
{
    assert(arena != NULL);
    assert(line != NULL);
    
    if (!arena || !line)
        return NULL;
    
    /* Find the equals sign */
    const char *eq = strchr(line, '=');
    if (!eq)
        return NULL;
    
    /* Move to the value part (after the equals sign) */
    const char *value_start = eq + 1;
    
    // Trim the value part
    char *trimmed_value = arena_trim(arena, value_start);
    if (!trimmed_value)
        return NULL;
    
    /* Check for quoted value */
    size_t trimmed_len = strlen(trimmed_value);
    if (trimmed_len >= 2 && trimmed_value[0] == '"' && trimmed_value[trimmed_len - 1] == '"') {
        /* Allocate space for string without quotes */
        char *unquoted = arena_alloc(arena, trimmed_len - 1); /* -1 because we're removing 2 quotes but need null terminator */
        if (!unquoted)
            return NULL;
        
        /* Copy the string without quotes */
        memcpy(unquoted, trimmed_value + 1, trimmed_len - 2);
        unquoted[trimmed_len - 2] = '\0';
        return unquoted;
    }
    
    return trimmed_value;
}

/**
 * Process a line from a configuration file - strip comments and trim whitespace
 * 
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Processed line, or NULL on error
 */
static char *arena_process_config_line(arena_t *arena, const char *line)
{
    assert(arena != NULL);
    assert(line != NULL);
    
    if (!arena || !line)
        return NULL;
    
    /* First strip comments, then trim whitespace */
    char *without_comments = arena_strip_comment(arena, line);
    if (!without_comments)
        return NULL;
    
    char *trimmed = arena_trim(arena, without_comments);
    
    /* We can return trimmed directly - no need to free without_comments
      as it's managed by the arena */
    return trimmed;
}

/**
 * Duplicate a string using arena memory
 * 
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
static inline char *arena_strdup(arena_t *arena, const char *str)
{
    if (!arena || !str) return NULL;
    
    size_t len = strlen(str);
    /* +1 for null terminator */
    char *dup = arena_alloc(arena, len + 1);
    if (dup) {
        memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}

#endif /* COOPER_H */