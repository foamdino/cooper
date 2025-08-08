/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>

#include "arena.h"
#include "arena_str.h"
#include "thread_util.h"

/* Maximum size of a log message */
#define MAX_LOG_MSG_SZ 1024
/* Maximum size of the log queue */
#define LOG_Q_SZ 1024

typedef enum log_level log_level_e;
typedef struct log_q log_q_t;
typedef struct log_system log_system_t;
typedef struct log_thread_params log_thread_params_t;

enum log_level
{
	LOG_LEVEL_DEBUG = 0,
	LOG_LEVEL_INFO  = 1,
	LOG_LEVEL_WARN  = 2,
	LOG_LEVEL_ERROR = 3,
	LOG_LEVEL_NONE  = 4 /* Disable all logging */
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

struct log_system
{
	log_q_t *queue;
	arena_t *arena;
	FILE *log_file;
	pthread_t log_thread;
	int initialized;
};

struct log_thread_params
{
	log_q_t *queue;
	FILE *log_file;
};

extern log_level_e current_log_level;

/* Initialize the logging system */
int init_log_system(log_q_t *queue, arena_t *arena, FILE *log_file);

/* Clean up the logging system
Assumes that the log system has been correct initialised via init_log_system
*/
void cleanup_log_system();

/* Core logging function that users don't need to call directly */
void log_message(log_level_e level, const char *file, int line, const char *fmt, ...);

/* For internal use or when you need to specify queue and arena */
void log_message_internal(log_q_t *queue,
                          arena_t *arena,
                          log_level_e level,
                          const char *file,
                          int line,
                          const char *fmt,
                          ...);

/* Log thread function - exported so can control when the thread starts/stops */
void *log_thread_func(void *arg);

/* Logging macros with compile-time control */
#ifdef ENABLE_DEBUG_LOGS
#define LOG_DEBUG(fmt, ...)                                                              \
	log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#ifdef ENABLE_INFO_LOGS
#define LOG_INFO(fmt, ...)                                                               \
	log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...) ((void)0)
#endif

/* Warning and error logs are always enabled */
#define LOG_WARN(fmt, ...)                                                               \
	log_message(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...)                                                              \
	log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* LOG_H */
