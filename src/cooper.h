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
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

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

typedef struct log_q log_q_t;
typedef struct trace_event trace_event_t;
typedef struct event_q event_q_t;
typedef struct method_stats method_stats_t;
typedef struct config config_t;
typedef struct agent_context agent_context_t;
typedef void *thread_fn(void *args);

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

struct trace_event
{
    char *class_sig;
    char *method_name;
    char *method_sig;
    int is_entry; /**< 1 for entry, 0 for exit */
};

struct event_q
{
    trace_event_t events[EVENT_Q_SZ];
    int hd;
    int tl;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
};

struct method_stats
{
    char *signature;
    int entry_count;
    int exit_count;
};

struct agent_context
{
    int event_counter;              /**< Counter for nth samples */
    method_stats_t full_samples[FULL_SAMPLE_SZ]; /**< Full event samples */
    int full_hd;                    /**< Head index for full samples */
    int full_count;                 /**< Number of full samples */
    method_stats_t nth_samples[NTH_SAMPLE_SZ];   /**< Nth event samples */
    int nth_hd;                     /**< Head index for nth samples */
    int nth_count;                  /**< Number of nth samples */
    jvmtiEnv *jvmti_env;            /**< JVMTI environment */
    char **method_filters;          /**< Method filter list */
    int num_filters;                /**< Number of filters */
    log_q_t log_queue;              /**< Logging queue */
    FILE *log_file;                 /**< Log output file */
    pthread_t log_thread;           /**< Logging thread */
    event_q_t event_queue;          /**< Event queue */
    pthread_t event_thread;         /**< Event processing thread */
    pthread_t export_thread;        /**< Export thread */
    pthread_mutex_t samples_lock;   /**< Lock for sample arrays */
    config_t config;                /**< Agent configuration */
    arena_t *exception_arena;       /**< Arena for exception memory allocation */
    arena_t *log_arena;             /**< Arena for log strings memory allocation */
    arena_t *event_arena;           /**< Arena for events memory allocation */
    arena_t *sample_arena;          /**< Arena for sample strings (full_sig etc) */
    arena_t *config_arena;          /**< Arena for config file strings (filters etc) */
};

/* jmvti callback functions */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value);
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location);

int should_trace_method(agent_context_t *ctx, const char *class_signature, const char *method_name, const char *method_signature);
int load_config(agent_context_t *ctx, const char *cf);
void cleanup(agent_context_t *ctx);
int start_thread(pthread_t *thread, thread_fn *tf, char *name, agent_context_t *ctx);

int init_log_q(agent_context_t *ctx);
void log_enq(agent_context_t *ctx, const char *msg);
char *log_deq(agent_context_t *ctx);
void *log_thread_func(void *arg);
void cleanup_log_system(agent_context_t *ctx);
void init_samples(agent_context_t *ctx);
void cleanup_samples(agent_context_t *ctx);
int init_event_q(agent_context_t *ctx);
void event_enq(agent_context_t *ctx, const char *class_sig, const char *method_name, const char *method_sig, int is_entry);
int event_deq(agent_context_t *ctx, trace_event_t *e);
void *event_thread_func(void *arg);
void cleanup_event_system(agent_context_t *ctx);
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
    
    // Find the comment marker
    const char *comment = strchr(str, '#');
    size_t len;
    
    if (comment) {
        len = comment - str;
    } else {
        len = strlen(str);
    }
    
    // Allocate and copy the substring
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
    
    // Skip leading whitespace
    while (isspace((unsigned char)*str))
        str++;
    
    // All whitespace or empty string
    if (*str == '\0') {
        char *result = arena_alloc(arena, 1);
        if (result)
            *result = '\0';
        return result;
    }
    
    // Find the end of the string
    size_t len = strlen(str);
    const char *end = str + len - 1;
    
    // Move backward to find the last non-whitespace character
    while (end > str && isspace((unsigned char)*end))
        end--;
    
    // Calculate the trimmed length
    size_t trimmed_len = end - str + 1;
    
    // Allocate and copy the trimmed string
    char *result = arena_alloc(arena, trimmed_len + 1);
    if (!result)
        return NULL;
    
    memcpy(result, str, trimmed_len);
    result[trimmed_len] = '\0';
    
    return result;
}

/**
 * Extract value part from a "key = value" string and trim it, using arena allocation
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
    
    // Find the equals sign
    const char *eq = strchr(line, '=');
    if (!eq)
        return NULL;
    
    // Move to the value part (after the equals sign)
    const char *value_start = eq + 1;
    
    // Trim the value part
    return arena_trim(arena, value_start);
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
    
    // First strip comments, then trim whitespace
    char *without_comments = arena_strip_comment(arena, line);
    if (!without_comments)
        return NULL;
    
    char *trimmed = arena_trim(arena, without_comments);
    
    // We can return trimmed directly - no need to free without_comments
    // as it's managed by the arena
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