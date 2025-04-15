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
    arena_t *exception_arena;        /**< Arena for exception memory allocation */
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


/* extern char *strip_comment(char *str);
   extern char *trim(char *str);
   extern char *extract_and_trim_value(char *line);
   extern int set_config_string(char **dest, const char *value); */

/**
 * Strip trailing comment from a string (returns pointer to start, modifies in place)
 * 
 * @param str pointer to check for comment start
 */
static inline char *strip_comment(char *str) 
{
    assert(str != NULL);

    if (str == NULL)
        return NULL;

    char *comment = strchr(str, '#');
    if (comment)
        *comment = '\0'; /* Truncate at comment start */

    return str;
}

/**
 * Strip trailing comment from a string
 * 
 * @param str pointer to check for comment start
 * @return pointer to a newly allocated string
 */
static inline char *strip_comment_safe(const char *str)
{
    assert(str!= NULL);
    if (str == NULL)
        return NULL;

    const char *comment = strchr(str, '#');
    size_t len;

    if (comment) {
        len = comment - str;
    } else {
        len = strlen(str);
    }

    char *new_str = (char *)malloc(len + 1);
    if (new_str == NULL) {
        return NULL; /* Allocation failed */
    }
    strncpy(new_str, str, len);
    new_str[len] = '\0';

    return new_str;
}

/**
 * Trim whitespace from string 
 * 
 * @param str pointer to string to trim
 * @param max_len maximum length of string supported
 * 
 * @retval trimmed str pointer
 */
static inline char *trim(char *str, size_t max_len)
{
    assert(str != NULL);

    char *start = NULL;
    char *end = NULL;
    size_t len = 0;

    if (str == NULL)
        return NULL;

    /* Skip leading whitespace */
    start = str;
    while ((*start == ' ' || *start == '\t' || *start == '\n') && len < max_len) 
    {
        start++;
        len++;
    }

    /* If str is empty just return it */
    if (*start == '\0' || len >= max_len)
        return start;

    /* Find the end of the string */
    end = start;
    char *last_non_whitespace = NULL;

    /* Track the last non-whitespace character */
    while (*end != '\0' && len < max_len) 
    {
        if (*end != ' ' && *end != '\t' && *end != '\n')
            last_non_whitespace = end;
        
        end++;
        len++;
    }
    
    /* If we found non-whitespace characters, null-terminate after the last one */
    if (last_non_whitespace != NULL)
        *(last_non_whitespace + 1) = '\0';
    
    return start;
}

static inline char *trim_safe(const char *str)
{
    assert(str!= NULL);
    if (str == NULL)
        return NULL;

    size_t len = strlen(str);
    size_t start = 0;
    size_t end = len;

    /* Skip leading whitespace */
    while (start < len && isspace((unsigned char)str[start])) {
        start++;
    }

    /* Skip trailing whitespace */
    while (end > start && isspace((unsigned char)str[end - 1])) {
        end--;
    }

    size_t trimmed_len = end - start;
    char *trimmed_str = (char *)malloc(trimmed_len + 1);
    if (trimmed_str == NULL) {
        return NULL; /* Allocation failed */
    }
    strncpy(trimmed_str, &str[start], trimmed_len);
    trimmed_str[trimmed_len] = '\0';

    return trimmed_str;
}

/**
 * Extract and trim the value from a key-value pair (e.g., "method = \"file\" # comment")
 */ 
static inline char *extract_and_trim_value(char *line)
{
    assert(line != NULL);

    if (line == NULL)
        return NULL;
    
    char *eq = strchr(line, '=');
    if (!eq) 
        return NULL; /* No '=' found */

    char *value = eq + 1;
    value = trim(value, MAX_STR_LEN); /* Trim leading/trailing whitespace */

    /* Handle quoted strings */
    if (value[0] == '"') 
    {
        value++; /* Skip opening quote */
        char *end = strchr(value, '"');
        if (end) *end = '\0'; /* Remove closing quote */
        else return NULL; /* Malformed: no closing quote */
    }

    return value[0] == '\0' ? NULL : value; /* Return NULL if empty */
}

static inline char *extract_and_trim_value_safe(const char *line)
{
    assert(line!= NULL);
    if (line == NULL)
        return NULL;

    const char *eq = strchr(line, '=');
    if (!eq)
        return NULL; /* No '=' found */

    const char *value_ptr = eq + 1;
    char *trimmed_value = trim_safe(value_ptr);
    if (trimmed_value == NULL) {
        return NULL;
    }

    size_t trimmed_len = strlen(trimmed_value);
    if (trimmed_len == 0) {
        free(trimmed_value);
        return NULL; /* Empty value after trim */
    }

    if (trimmed_len > 0 && trimmed_value[0] == '"') {
        if (trimmed_len <= 1) {
            free(trimmed_value);
            return NULL; /* Empty quotes */
        }
        const char *end_quote = strchr(&trimmed_value[1], '"');
        if (!end_quote) {
            free(trimmed_value);
            return NULL; /* Malformed: no closing quote */
        }
        size_t value_len = end_quote - &trimmed_value[1];
        if (value_len >= MAX_STR_LEN) {
            free(trimmed_value);
            return NULL; /* Value too long */
        }
        char *extracted_value = (char *)malloc(value_len + 1);
        if (extracted_value == NULL) {
            free(trimmed_value);
            return NULL; /* Allocation failed */
        }
        strncpy(extracted_value, &trimmed_value[1], value_len);
        extracted_value[value_len] = '\0';
        free(trimmed_value);
        return extracted_value;
    } else {
        if (trimmed_len >= MAX_STR_LEN) {
            free(trimmed_value);
            return NULL; /* Value too long */
        }
        return trimmed_value; /* Caller is now responsible for freeing */
    }
}

/**
 * Helper function to set config strings with error handling
 */
static inline int set_config_string(char **dest, const char *value)
{
    assert(value != NULL);
    
    char *new_value = strdup(value);
    if (!new_value) return 0; /* Failure */
    if (*dest) free(*dest);
    *dest = new_value;
    return 1; /* Success */
}

#endif /* COOPER_H */