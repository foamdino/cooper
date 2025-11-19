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
    .ring = NULL, .log_file = NULL, .log_thread = 0, .initialized = 0};

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
	mpsc_ring_t *ring           = params->ring;
	FILE *log_file              = params->log_file;

	/* Params are arena allocated, so no need to free */

	while (1)
	{
		uint32_t handle;
		int res = mpsc_ring_consume(ring, &handle);

		if (res == MPSC_OK)
		{
			char *msg = mpsc_ring_get(ring, handle);
			/* Write message to log file */
			if (msg)
			{
				fprintf(log_file, "%s", msg);
				fflush(log_file);
			}
			mpsc_ring_release(ring, handle);
		}
		else if (res == MPSC_EMPTY)
		{
			/*
			 * Check if we should exit.
			 * In a lock-free system without condition variables, we must
			 * poll. To avoid burning CPU, we sleep briefly.
			 */
			if (!log_system.initialized) /* crude shutdown signal check */
				break;

			usleep(1000); /* 1ms sleep */
		}
		else if (res == MPSC_BUSY)
		{
			/* Producer reserved but hasn't committed. Yield and retry. */
			sched_yield();
		}
	}

	return NULL;
}

/**
 * Initialize the logging system
 *
 * @param ring          Pointer to log ring to initialize
 * @param arena         Arena for allocating thread parameters
 * @param log_file      log file, or NULL for stdout
 * @return              0 on success, non-zero on failure
 */
int
init_log_system(mpsc_ring_t *ring, arena_t *arena, FILE *log_file)
{
	assert(ring != NULL);
	assert(arena != NULL);

	/* Open log file or use stdout */
	if (!log_file)
		log_file = stdout;

	/* Save state for global access early (safe single-threaded init) */
	log_system.ring     = ring;
	log_system.log_file = log_file;

	/* Create thread parameters */
	log_thread_params_t *params = arena_alloc(arena, sizeof(log_thread_params_t));
	if (!params)
	{
		fprintf(stderr,
		        "ERROR: Failed to allocate memory for log thread parameters\n");
		goto error;
	}

	params->ring     = ring;
	params->log_file = log_file;

	/* Start the logging thread */
	pthread_t log_thread;
	int err = pthread_create(&log_thread, NULL, log_thread_func, params);
	if (err != 0)
	{
		fprintf(stderr, "ERROR: Failed to start logging thread: %d\n", err);
		/* Cannot free arena memory individually */
		goto error;
	}

	/* Save state for global access */
	log_system.log_thread  = log_thread;
	log_system.initialized = 1;

	return 0;

error:
	if (log_file != stdout && log_file != stderr)
		fclose(log_file);

	return 1;
}

/**
 * Clean up the logging system
 */
void
cleanup_log_system()
{
	/* Signal shutdown */
	log_system.initialized = 0;

	/* Wait for thread to terminate */
	int join_result = safe_thread_join(log_system.log_thread, 3);
	if (join_result != 0)
	{
		/* If thread didn't terminate in time, proceed anyway */
		fprintf(stderr, "WARNING: Log thread did not terminate within timeout\n");
	}

	/* Purge remaining messages */
	uint32_t handle;
	while (mpsc_ring_consume(log_system.ring, &handle) == MPSC_OK)
	{
		char *msg = mpsc_ring_get(log_system.ring, handle);
		fprintf(log_system.log_file, "%s", msg);
		mpsc_ring_release(log_system.ring, handle);
	}

	if (log_system.log_file != stdout && log_system.log_file != stderr)
		fclose(log_system.log_file);

	/* Reset global state */
	log_system.ring     = NULL;
	log_system.log_file = NULL;
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

	/* Reserve a slot in the ring buffer */
	uint32_t handle;
	if (mpsc_ring_reserve(log_system.ring, &handle) != MPSC_OK)
	{
		/* Ring full, drop message */
		/* We could try to print to stderr but that might interleave badly */
		return;
	}

	char *buffer = mpsc_ring_get(log_system.ring, handle);

	/* Format directly into the ring buffer slot */
	int header_len = snprintf(buffer,
	                          MAX_LOG_MSG_SZ,
	                          "[%s] %s [%s:%d] ",
	                          level_names[level],
	                          timestamp,
	                          file ? file : "unknown",
	                          line);

	if (header_len < 0)
	{
		mpsc_ring_commit(log_system.ring, handle);
		return;
	}

	/* if header_len >= MAX_LOG_MSG_SZ then nothing can be written */
	if ((size_t)header_len >= MAX_LOG_MSG_SZ)
	{
		/* header truncated; ensure last byte is NUL and drop */
		buffer[MAX_LOG_MSG_SZ - 1] = '\0';
		mpsc_ring_commit(log_system.ring, handle);
		return;
	}

	/* remaining space for the message (include space for final newline and NUL) */
	size_t available = MAX_LOG_MSG_SZ - (size_t)header_len;

	va_list args;
	va_start(args, fmt);
	/* we pass available - 1 to vsnprintf so there's always room for trailing '\n' or
	 * '\0' */
	int rv = vsnprintf(
	    buffer + header_len, (available > 0) ? (available - 1) : 0, fmt, args);
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
		/* vsnprintf returns the would-be length; actual written is min(rv,
		 * available-1) */
		size_t wrote = (size_t)rv;
		if (wrote >= (available > 0 ? available - 1 : 0))
			actual_msg_len = (available > 0 ? available - 1 : 0);
		else
			actual_msg_len = wrote;
	}

	/* Ensure there's a newline at the end, if room. If not room, we already have a
	   truncated message and the last char is at buffer[MAX_LOG_MSG_SZ-2] (since we
	   reserved one for NUL). */
	size_t total_len = (size_t)header_len + actual_msg_len;
	if (total_len + 1 < MAX_LOG_MSG_SZ)
	{
		/* room for newline and NUL */
		if (buffer[total_len - 1] != '\n')
		{
			buffer[total_len]     = '\n';
			buffer[total_len + 1] = '\0';
		}
		else
			buffer[total_len] = '\0';
	}
	else
	{
		/* truncated — ensure NUL at final position */
		buffer[MAX_LOG_MSG_SZ - 1] = '\0';
	}

	/* Commit the message to the ring */
	mpsc_ring_commit(log_system.ring, handle);
}
