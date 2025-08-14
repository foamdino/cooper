/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "log.h"

/* Static level names for output */
static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};

/* Default is INFO level, can be changed at runtime */
log_level_e current_log_level = LOG_LEVEL_INFO;

/* Global logging system state */
static log_system_t log_system = {
    .queue = NULL, .arena = NULL, .log_file = NULL, .log_thread = 0, .initialized = 0};

/**
 * Logger thread function that writes messages from the log queue
 *
 * @param arg Pointer to log_thread_params_t
 * @return    NULL on thread completion
 */
void *
log_thread_func(void *arg)
{
	assert(arg != NULL);

	log_thread_params_t *params = (log_thread_params_t *)arg;
	q_t *queue                  = params->queue;
	FILE *log_file              = params->log_file;
	while (1)
	{
		q_entry_t *entry = q_deq(queue);
		if (entry)
		{
			if (entry->type == Q_ENTRY_LOG)
			{
				char *msg = (char *)entry->data;
				/* Write message to log file */
				if (msg)
				{
					fprintf(log_file, "%s", msg);
					fflush(log_file);
				}
			}
		}
	}

	return NULL;
}

/**
 * Initialize the logging system
 *
 * @param queue         Pointer to log queue to initialize
 * @param arena_head    Pointer to head of arena list
 * @param log_file      log file, or NULL for stdout
 * @return              0 on success, non-zero on failure
 */
int
init_log_system(q_t *queue, arena_t *arena, FILE *log_file)
{
	assert(queue != NULL);

	/* Initialize the queue */
	// TODO move this running flag into the worker status flags
	queue->running = 1;

	int err = q_init(queue);

	if (err != 0)
	{
		fprintf(stderr, "ERROR: Failed to init log queue: %d\n", err);
		return 1;
	}

	/* Open log file or use stdout */
	if (!log_file)
		log_file = stdout;

	/* Create thread parameters */
	log_thread_params_t *params = arena_alloc(arena, sizeof(log_thread_params_t));
	if (!params)
	{
		fprintf(stderr,
		        "ERROR: Failed to allocate memory for log thread parameters\n");
		goto error;
	}

	params->queue    = queue;
	params->log_file = log_file;

	/* Start the logging thread */
	pthread_t log_thread;
	err = pthread_create(&log_thread, NULL, log_thread_func, params);
	if (err != 0)
	{
		fprintf(stderr, "ERROR: Failed to start logging thread: %d\n", err);
		goto error;
	}

	/* Save state for global access */
	log_system.queue       = queue;
	log_system.arena       = arena;
	log_system.log_file    = log_file;
	log_system.log_thread  = log_thread;
	log_system.initialized = 1;

	return 0;

error:
	if (log_file != stdout && log_file != stderr)
		fclose(log_file);

	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->lock);
	return 1;
}

/**
 * Clean up the logging system
 *
 * @param queue      Pointer to log queue
 * @param log_file   File pointer to log output
 * @param log_thread Thread ID of logging thread
 */
void
cleanup_log_system()
{

	pthread_mutex_lock(&log_system.queue->lock);
	log_system.queue->running = 0;
	pthread_cond_broadcast(&log_system.queue->cond);
	pthread_mutex_unlock(&log_system.queue->lock);

	/* Wait for thread to terminate */
	int join_result = safe_thread_join(log_system.log_thread, 3);
	if (join_result != 0)
	{
		/* If thread didn't terminate in time, proceed anyway */
		fprintf(stderr, "WARNING: Log thread did not terminate within timeout\n");
	}

	/* Purge remaining messages */
	q_entry_t *entry;
	while ((entry = q_deq(log_system.queue)) != NULL)
	{
		if (entry->type == Q_ENTRY_LOG)
			fprintf(log_system.log_file, "%s\n", (char *)entry->data);
	}

	if (log_system.log_file != stdout && log_system.log_file != stderr)
		fclose(log_system.log_file);

	pthread_cond_destroy(&log_system.queue->cond);
	pthread_mutex_destroy(&log_system.queue->lock);

	/* Reset global state */
	log_system.queue       = NULL;
	log_system.arena       = NULL;
	log_system.log_file    = NULL;
	log_system.initialized = 0;
}

/**
 * Public API function for logging that uses the global log system
 */
void
log_message(log_level_e level, const char *file, int line, const char *fmt, ...)
{
	/* Skip if system not initialized or level is below current_log_level */
	if (!log_system.initialized || level < current_log_level)
		return;

	/* Get current timestamp */
	time_t now;
	struct tm tm_now;
	char timestamp[24]; /* Format: YYYY-MM-DD HH:MM:SS.mmm */

	time(&now);
	localtime_r(&now, &tm_now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

	/* Format the message with level, timestamp, location, and user message */
	char buffer[MAX_LOG_MSG_SZ];
	int header_len = snprintf(buffer,
	                          sizeof(buffer),
	                          "[%s] %s [%s:%d] ",
	                          level_names[level],
	                          timestamp,
	                          file ? file : "unknown",
	                          line);

	/* Header too long, can't proceed */
	if (header_len < 0 || header_len >= (int)sizeof(buffer))
		return;

	/* Add the user message with variable arguments */
	va_list args;
	va_start(args, fmt);
	int msg_len =
	    vsnprintf(buffer + header_len, sizeof(buffer) - header_len - 1, fmt, args);
	va_end(args);

	/* Formatting error */
	if (msg_len < 0)
		return;

	/* Ensure newline at the end */
	size_t total_len = header_len + msg_len;
	if (total_len > 0 && total_len < sizeof(buffer) - 2
	    && buffer[total_len - 1] != '\n')
	{
		buffer[total_len]     = '\n';
		buffer[total_len + 1] = '\0';
	}

	/* Enqueue the formatted message using global system state */
	q_entry_t *entry = arena_alloc(log_system.arena, sizeof(q_entry_t));
	char *log_msg    = arena_strdup(log_system.arena, buffer);

	entry->type = Q_ENTRY_LOG;
	entry->data = log_msg;
	q_enq(log_system.queue, entry);
}
