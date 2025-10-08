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
		char *msg        = NULL;

		/* Shutting down */
		if (!entry)
			break;

		if (entry->type == Q_ENTRY_LOG)
		{
			msg = (char *)entry->data;
			/* Write message to log file */
			if (msg)
			{
				fprintf(log_file, "%s", msg);
				fflush(log_file);
			}
		}

		/* Free mem back to arena */
		pthread_mutex_lock(&log_system.arena_lock);
		arena_free(log_system.arena, msg);
		arena_free(log_system.arena, entry);
		pthread_mutex_unlock(&log_system.arena_lock);
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

	/* Initialize the arena lock BEFORE any use */
	if (pthread_mutex_init(&log_system.arena_lock, NULL) != 0)
	{
		fprintf(stderr, "ERROR: pthread_mutex_init failed\n");
		return 1;
	}

	/* Save state for global access early (safe single-threaded init) */
	log_system.queue    = queue;
	log_system.arena    = arena;
	log_system.log_file = log_file;

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
	log_system.log_thread  = log_thread;
	log_system.initialized = 1;

	return 0;

error:
	if (log_file != stdout && log_file != stderr)
		fclose(log_file);

	pthread_cond_destroy(&queue->cond);
	pthread_mutex_destroy(&queue->lock);
	pthread_mutex_destroy(&log_system.arena_lock);
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
	pthread_mutex_destroy(&log_system.arena_lock);

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
    if (!log_system.initialized || level < current_log_level)
        return;

    time_t now;
    struct tm tm_now;
    char timestamp[24];
    time(&now);
    localtime_r(&now, &tm_now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    char buffer[MAX_LOG_MSG_SZ];
    int header_len = snprintf(buffer,
                              sizeof(buffer),
                              "[%s] %s [%s:%d] ",
                              level_names[level],
                              timestamp,
                              file ? file : "unknown",
                              line);
    if (header_len < 0)
        return;

    /* if header_len >= sizeof(buffer) then nothing can be written */
    if ((size_t)header_len >= sizeof(buffer)) 
	{
        /* header truncated; ensure last byte is NUL and drop */
        buffer[sizeof(buffer) - 1] = '\0';
        /* optionally fallback to fprintf() here */
        return;
    }

    /* remaining space for the message (include space for final newline and NUL) */
    size_t available = sizeof(buffer) - (size_t)header_len;

    va_list args;
    va_start(args, fmt);
    /* we pass available - 1 to vsnprintf so there's always room for trailing '\n' or '\0' */
    int rv = vsnprintf(buffer + header_len, (available > 0) ? (available - 1) : 0, fmt, args);
    va_end(args);

	/* formatting error */
    if (rv < 0)
        buffer[header_len] = '\0';

    /* actual number of characters written into the buffer (excluding NUL) */
    size_t actual_msg_len;
    if (rv < 0)
        actual_msg_len = strlen(buffer + header_len);
    else 
	{
        /* vsnprintf returns the would-be length; actual written is min(rv, available-1) */
        size_t wrote = (size_t)rv;
        if (wrote >= (available > 0 ? available - 1 : 0))
            actual_msg_len = (available > 0 ? available - 1 : 0);
        else
            actual_msg_len = wrote;
    }

    /* Ensure there's a newline at the end, if room. If not room, we already have a truncated message and
       the last char is at buffer[sizeof(buffer)-2] (since we reserved one for NUL). */
    size_t total_len = (size_t)header_len + actual_msg_len;
    if (total_len + 1 < sizeof(buffer)) 
	{
        /* room for newline and NUL */
        if (buffer[total_len - 1] != '\n') 
		{
            buffer[total_len] = '\n';
            buffer[total_len + 1] = '\0';
            total_len += 1;
        } 
		else
            buffer[total_len] = '\0';

    } 
	else 
	{
        /* truncated — ensure NUL at final position */
        buffer[sizeof(buffer) - 1] = '\0';
        total_len = strlen(buffer); /* safe fallback */
    }

    /* Now buffer is a well-formed, NUL-terminated string of length total_len */

    pthread_mutex_lock(&log_system.arena_lock);
    q_entry_t *entry = arena_alloc(log_system.arena, sizeof(q_entry_t));
    if (!entry) 
	{
        pthread_mutex_unlock(&log_system.arena_lock);
        fprintf(stderr, "WARNING: log arena OOM, dropping message: %s", buffer);
        return;
    }

    char *log_msg = arena_strdup(log_system.arena, buffer);
    if (!log_msg) 
	{
        arena_free(log_system.arena, entry);
        pthread_mutex_unlock(&log_system.arena_lock);
        fprintf(stderr, "WARNING: log arena OOM (msg), dropping: %s", buffer);
        return;
    }
    pthread_mutex_unlock(&log_system.arena_lock);

    entry->type = Q_ENTRY_LOG;
    entry->data = log_msg;

    if (q_enq(log_system.queue, entry) != 0) 
	{
        pthread_mutex_lock(&log_system.arena_lock);
        arena_free(log_system.arena, log_msg);
        arena_free(log_system.arena, entry);
        pthread_mutex_unlock(&log_system.arena_lock);
        fprintf(stderr, "WARNING: logging queue full, dropping: %s", log_msg);
    }
}

