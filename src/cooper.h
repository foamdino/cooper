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

#define config_file "trace.ini"
#define EVENT_Q_SZ 2048 /**< An event q buffer */
#define FULL_SAMPLE_SZ 1024 /**< The max entries for the every sample buffer */
#define NTH_SAMPLE_SZ 256 /**< The max entries for the nth sample buffer */
#define MAX_SIG_SZ 1024 /**< The max size of a class/method sig we are willing to tolerate */
#define MAX_LOG_MSG_SZ 1024 /**< The max size of a trace message we will tolerate */
#define LOG_Q_SZ 1024 /**< Length of log q */
#define LOG(fmt, ...) do { \
    char msg[MAX_LOG_MSG_SZ]; \
    int len = snprintf(msg, sizeof(msg), "[JMVTI] " fmt, ##__VA_ARGS__); \
    if (len >= 0 && len < MAX_LOG_MSG_SZ) { \
        log_enq(msg); \
    } \
} while (0)

typedef struct log_q log_q_t;
typedef struct trace_event trace_event_t;
typedef struct event_q event_q_t;
typedef struct method_stats method_stats_t;
typedef struct config config_t;
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

/**
 * Strip trailing comment from a string (returns pointer to start, modifies in place)
 * 
 * @param str pointer to check for comment start
 */
static inline char *strip_comment(char *str) {
    char *comment = strchr(str, '#');
    if (comment)
        *comment = '\0'; /* Truncate at comment start */

    return str;
}

/**
 * Trim whitespace from string 
 * 
 * @param str pointer to string to trim
 * 
 * @retval trimmed str pointer
 */
static inline char *trim(char *str)
{
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) -1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n'))
        *end-- = '\0';
    
    return str;
}

// Extract and trim the value from a key-value pair (e.g., "method = \"file\" # comment")
static char *extract_and_trim_value(char *line, const char *key) {
    char *eq = strchr(line, '=');
    if (!eq) 
        return NULL; // No '=' found

    char *value = eq + 1;
    value = trim(value); // Trim leading/trailing whitespace

    // Handle quoted strings
    if (value[0] == '"') 
    {
        value++; // Skip opening quote
        char *end = strchr(value, '"');
        if (end) *end = '\0'; // Remove closing quote
        else return NULL; // Malformed: no closing quote
    }

    return value[0] == '\0' ? NULL : value; // Return NULL if empty
}

#endif /* COOPER_H */