/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "log.h"

/* Static level names for output */
static const char *level_names[] = 
{
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR"
};

/* Default is INFO level, can be changed at runtime */
log_level_e current_log_level = LOG_LEVEL_INFO;

/* Global logging system state */
static log_system_t log_system = {
    .queue = NULL,
    .arena = NULL,
    .log_file = NULL,
    .log_thread = 0,
    .initialized = 0
};

/**
 * Enqueue a message to the log queue
 *
 * @param queue      Log queue
 * @param arena_head Head of the arena list
 * @param msg        Message to enqueue (will be copied to arena memory)
 */
static void log_enq(log_q_t *queue, arena_t *arena, const char *msg)
{
    assert(queue != NULL);
    assert(arena != NULL);
    assert(msg != NULL);


    /* We cannot do anything without a queue */
    if (!queue)
    {
        fprintf(stderr, "ERROR: No queue to log to!!");
        return;
    }

    /* Obtain lock to queue */
    pthread_mutex_lock(&queue->lock);

    if (!arena)
    {
        pthread_mutex_unlock(&queue->lock);
        return;
    }

    if (queue->count < LOG_Q_SZ)
    {
        queue->messages[queue->hd] = arena_strdup(arena, msg);
        if (queue->messages[queue->hd])
        {
            queue->hd = (queue->hd + 1) % LOG_Q_SZ;
            queue->count++;
            pthread_cond_signal(&queue->cond);
        }
    }
    else /* Drop messages when queue is full */
    {
        /* Write to stderr as last resort */
        fprintf(stderr, "WARNING: logging queue full, dropping: %s\n", msg);
    }

    pthread_mutex_unlock(&queue->lock);
}

/**
 * Dequeue a message from the log queue
 * 
 * @param queue Log queue
 * @return      Pointer to the dequeued message, or NULL if queue is empty
 */
static char *log_deq(log_q_t *queue)
{
    assert(queue != NULL);

    char *msg = NULL;
    pthread_mutex_lock(&queue->lock);

    if (queue->count > 0)
    {
        msg = queue->messages[queue->tl];
        queue->messages[queue->tl] = NULL;
        queue->tl = (queue->tl + 1) % LOG_Q_SZ;
        queue->count--;
    }

    pthread_mutex_unlock(&queue->lock);
    return msg;
}

/**
 * Logger thread function that writes messages from the log queue
 * 
 * @param arg Pointer to log_thread_params_t
 * @return    NULL on thread completion
 */
void *log_thread_func(void *arg)
{
    assert(arg != NULL);

    log_thread_params_t *params = (log_thread_params_t *)arg;
    log_q_t *queue = params->queue;
    FILE *log_file = params->log_file;

    /* We don't need the params structure anymore */
    free(params);

    while (1)
    {
        pthread_mutex_lock(&queue->lock);

        /* Should we exit? */
        if (!queue->running && queue->count == 0)
        {
            pthread_mutex_unlock(&queue->lock);
            break;
        }

        /* Wait for messages when queue is empty */
        while (queue->running && queue->count == 0)
            pthread_cond_wait(&queue->cond, &queue->lock);

        if (queue->count > 0)
        {
            char *msg = queue->messages[queue->tl];
            queue->messages[queue->tl] = NULL;
            queue->tl = (queue->tl + 1) % LOG_Q_SZ;
            queue->count--;
            pthread_mutex_unlock(&queue->lock);

            /* Write message to log file */
            if (msg) {
                fprintf(log_file, "%s", msg);
                fflush(log_file);
            }
        }
        else /* Nothing to do so release lock */
            pthread_mutex_unlock(&queue->lock);    
    }

    return NULL;
}

/**
 * Helper function to join a thread with timeout
 *
 * @param thread    Thread ID to join
 * @param timeout   Timeout in seconds
 * @return          0 on success, error code on failure
 */
static int safe_thread_join(pthread_t thread, int timeout)
{
    /* First try to join without any tricks (normal path) */
    int result = pthread_join(thread, NULL);
    if (result == 0) {
        return 0; /* Joined successfully */
    }
    
    /* If we can't join (thread might be detached or already joined) */
    if (result == EINVAL || result == ESRCH) {
        return result; /* Return the error code */
    }
    
    /* For threads that can't be joined immediately but timeout > 0 */
    if (timeout > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout;
        
        /* Sleep in small increments and retry joining */
        while (timeout > 0) {
            /* Sleep for 100ms at a time */
            usleep(100000);
            
            /* Try joining again */
            result = pthread_join(thread, NULL);
            if (result == 0) {
                return 0; /* Successfully joined */
            }
            
            /* If thread is invalid or already joined/detached, return */
            if (result == EINVAL || result == ESRCH) {
                return result;
            }
            
            /* Check if we've exceeded the timeout */
            struct timespec current;
            clock_gettime(CLOCK_REALTIME, &current);
            if (current.tv_sec >= ts.tv_sec && 
                current.tv_nsec >= ts.tv_nsec) {
                break;
            }
        }
    }

    /* If we reach here, we couldn't join within the timeout period */
    return ETIMEDOUT;
}

/**
 * Initialize the logging system
 * 
 * @param queue         Pointer to log queue to initialize
 * @param arena_head    Pointer to head of arena list
 * @param log_file      log file, or NULL for stdout
 * @return              0 on success, non-zero on failure
 */
int init_log_system(log_q_t *queue, arena_t *arena, FILE *log_file)
{
    assert(queue != NULL);
    
    /* Initialize the queue */
    queue->hd = 0;
    queue->tl = 0;
    queue->count = 0;
    queue->running = 1;
    memset(queue->messages, 0, sizeof(queue->messages));

    int err;

    err = pthread_mutex_init(&queue->lock, NULL);
    if (err != 0)
    {
        fprintf(stderr, "ERROR: Failed to init log queue mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&queue->cond, NULL);
    if (err != 0)
    {
        fprintf(stderr, "ERROR: Failed to init log queue condition: %d\n", err);
        pthread_mutex_destroy(&queue->lock);
        return 1;
    }

    /* Open log file or use stdout */
    if (!log_file)
        log_file = stdout;
    
    /* Create thread parameters */
    log_thread_params_t *params = malloc(sizeof(log_thread_params_t));
    if (!params) 
    {
        fprintf(stderr, "ERROR: Failed to allocate memory for log thread parameters\n");
        goto error;
    }
    
    params->queue = queue;
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
    log_system.queue = queue;
    log_system.arena = arena;
    log_system.log_file = log_file;
    log_system.log_thread = log_thread;
    log_system.initialized = 1;

    return 0;

error:
    if (params) free(params);
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
void cleanup_log_system()
{
    
    pthread_mutex_lock(&log_system.queue->lock);
    log_system.queue->running = 0;
    pthread_cond_broadcast(&log_system.queue->cond);
    pthread_mutex_unlock(&log_system.queue->lock);
    
    /* Wait for thread to terminate */
    int join_result = safe_thread_join(log_system.log_thread, 2);
    if (join_result != 0) 
    {
        /* If thread didn't terminate in time, proceed anyway */
        fprintf(stderr, "WARNING: Log thread did not terminate within timeout\n");
    }

    /* Purge remaining messages */
    char *msg;
    while ((msg = log_deq(log_system.queue)) != NULL)
    {
        fprintf(log_system.log_file, "%s\n", msg);
    }

    if (log_system.log_file != stdout && log_system.log_file != stderr)
        fclose(log_system.log_file);

    pthread_cond_destroy(&log_system.queue->cond);
    pthread_mutex_destroy(&log_system.queue->lock);
    
    /* Reset global state */
    log_system.queue = NULL;
    log_system.arena = NULL;
    log_system.log_file = NULL;
    log_system.initialized = 0;
}

/**
 * Format and enqueue a log message
 * 
 * @param queue      Pointer to log queue
 * @param arena      Log arena
 * @param level      Log level
 * @param file       Source file name
 * @param line       Source line number
 * @param fmt        Format string
 * @param ...        Format arguments
 */
void log_message_internal(log_q_t *queue, arena_t *arena, log_level_e level,
    const char *file, int line, const char *fmt, ...)
{
    /* Skip if level is below current_log_level */
    if (level < current_log_level || !queue)
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
    int header_len = snprintf(buffer, sizeof(buffer), 
                    "[%s] %s [%s:%d] ", 
                    level_names[level], timestamp, 
                    file ? file : "unknown", line);
                    
    /* Header too long, can't proceed */
    if (header_len < 0 || header_len >= (int)sizeof(buffer))
        return;

    /* Add the user message with variable arguments */
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(buffer + header_len, sizeof(buffer) - header_len - 1, fmt, args);
    va_end(args);

    /* Formatting error */
    if (msg_len < 0)
        return;

    /* Ensure newline at the end */
    size_t total_len = header_len + msg_len;
    if (total_len > 0 && total_len < sizeof(buffer) - 2 && buffer[total_len - 1] != '\n') 
    {
        buffer[total_len] = '\n';
        buffer[total_len + 1] = '\0';
    }

    /* Enqueue the formatted message */
    log_enq(queue, arena, buffer);
}

/**
 * Public API function for logging that uses the global log system
 */
void log_message(log_level_e level, const char *file, int line, const char *fmt, ...)
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
    int header_len = snprintf(buffer, sizeof(buffer), 
                              "[%s] %s [%s:%d] ", 
                              level_names[level], timestamp, 
                              file ? file : "unknown", line);
      
    /* Header too long, can't proceed */
    if (header_len < 0 || header_len >= (int)sizeof(buffer))
        return;
    
    /* Add the user message with variable arguments */
    va_list args;
    va_start(args, fmt);
    int msg_len = vsnprintf(buffer + header_len, sizeof(buffer) - header_len - 1, fmt, args);
    va_end(args);
    
    /* Formatting error */
    if (msg_len < 0)
        return;
    
    /* Ensure newline at the end */
    size_t total_len = header_len + msg_len;
    if (total_len > 0 && total_len < sizeof(buffer) - 2 && buffer[total_len - 1] != '\n') 
    {
        buffer[total_len] = '\n';
        buffer[total_len + 1] = '\0';
    }
    
    /* Enqueue the formatted message using global system state */
    log_enq(log_system.queue, log_system.arena, buffer);
}
