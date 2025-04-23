/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "arena.h"

static agent_context_t *global_ctx = NULL; /* Single global context */

/* Thread-local storage key and initialization mutex */
static pthread_key_t sample_key;
static int tls_initialized = 0;
static pthread_mutex_t tls_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialize thread-local storage */
static void init_thread_local_storage() {
    /* Double-checked locking pattern */
    if (!tls_initialized) {
        pthread_mutex_lock(&tls_init_mutex);
        if (!tls_initialized) {
            /* The 'free' function will be automatically called when a thread exits */
            pthread_key_create(&sample_key, free);
            tls_initialized = 1;
        }
        pthread_mutex_unlock(&tls_init_mutex);
    }
}

/* Get the thread-local sample structure */
static method_sample_t *get_thread_local_sample() {
    if (!tls_initialized) {
        init_thread_local_storage();
    }
    
    method_sample_t *sample = pthread_getspecific(sample_key);
    if (!sample) {
        /* First time this thread is accessing the key */
        // TODO fix this calloc as it is not correctly free'd later
        sample = calloc(1, sizeof(method_sample_t));
        if (sample) {
            sample->method_index = -1;  /* Not sampling */
            pthread_setspecific(sample_key, sample);
        }
    }
    
    return sample;
}

/* Get current time in nanoseconds */
static uint64_t get_current_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Mock implementations for memory and CPU metrics */
static uint64_t get_current_memory() {
    /* In a real implementation, this would use system calls to get memory usage */
    return 0;
}

static uint64_t get_current_cpu_cycles() {
    /* In a real implementation, this would use CPU performance counters */
    return 0;
}

/* Record method execution metrics */
void record_method_execution(agent_context_t *ctx, int method_index, 
    uint64_t exec_time_ns, uint64_t memory_bytes, uint64_t cycles) {

    method_metrics_soa_t *metrics = ctx->metrics;

    /* Check for valid index */
    if (method_index < 0 || (size_t)method_index >= metrics->count) {
        return;
    }

    /* Lock metrics for thread safety */
    pthread_mutex_lock(&ctx->samples_lock);

    /* Update sample count */
    metrics->sample_counts[method_index]++;

    /* Update timing metrics if enabled */
    if (metrics->metric_flags[method_index] & METRIC_FLAG_TIME) {
        metrics->total_time_ns[method_index] += exec_time_ns;

        /* Update min/max */
        if (exec_time_ns < metrics->min_time_ns[method_index]) {
            metrics->min_time_ns[method_index] = exec_time_ns;
        }
        if (exec_time_ns > metrics->max_time_ns[method_index]) {
            metrics->max_time_ns[method_index] = exec_time_ns;
        }
    }

    /* Update memory metrics if enabled */
    if (metrics->metric_flags[method_index] & METRIC_FLAG_MEMORY) {
        metrics->alloc_bytes[method_index] += memory_bytes;
        if (memory_bytes > metrics->peak_memory[method_index]) {
            metrics->peak_memory[method_index] = memory_bytes;
        }
    }

    /* Update CPU metrics if enabled */
    if (metrics->metric_flags[method_index] & METRIC_FLAG_CPU) {
        metrics->cpu_cycles[method_index] += cycles;
    }

    pthread_mutex_unlock(&ctx->samples_lock);
}

/**
 * Helper function to safely join a thread with timeout
 * Works across different platforms without relying on non-portable extensions
 *
 * @param thread    Thread ID to join
 * @param timeout   Timeout in seconds
 * @return          0 on success, error code on failure
 */
static int safe_thread_join(pthread_t thread, int timeout)
{
    /* First try to join without any tricks (this is the normal, clean path) */
    int result = pthread_join(thread, NULL);
    if (result == 0) {
        return 0; /* Joined successfully */
    }
    
    /* If we can't join (thread might be detached or already joined) */
    if (result == EINVAL || result == ESRCH) {
        return result; /* Return the error code */
    }
    
    /* For threads that can't be joined immediately but timeout > 0,
       we need to wait and retry */
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

int init_log_q(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    ctx->log_queue.hd = 0;
    ctx->log_queue.tl = 0;
    ctx->log_queue.count = 0;
    ctx->log_queue.running = 1;

    int err;

    err = pthread_mutex_init(&ctx->log_queue.lock, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&ctx->log_queue.cond, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q condition: %d\n", err);
        return 1;
    }

    /* TODO: This is hardcoded to STDOUT for now*/
    ctx->log_file = stdout;
    return 0;
}

/**
 * Enqueue a msg to the log q
 * 
 * @param msg Pointer to msg to add
 * 
 */
void log_enq(agent_context_t *ctx, const char *msg)
{
    assert(ctx != NULL);
    assert(msg != NULL);
    
    /* Obtain lock to q */
    pthread_mutex_lock(&ctx->log_queue.lock);

    arena_t *arena = find_arena(ctx->arena_head, "log_arena");

    if (ctx->log_queue.count < LOG_Q_SZ)
    {
        ctx->log_queue.messages[ctx->log_queue.hd] = arena_strdup(arena, msg);
        if (ctx->log_queue.messages[ctx->log_queue.hd])
        {
            ctx->log_queue.hd = (ctx->log_queue.hd + 1) % LOG_Q_SZ;
            ctx->log_queue.count++;
            pthread_cond_signal(&ctx->log_queue.cond);
        }
    }
    else /* Drop messages when q is full */
        fprintf(stderr, "WARNING: logging q full, dropping: %s\n", msg);

    pthread_mutex_unlock(&ctx->log_queue.lock);
}

/**
 * Deuque a message from the log q
 * 
 * @retval Pointer to a char message
 */
char *log_deq(agent_context_t *ctx)
{
    assert(ctx != NULL);

    char *msg = NULL;
    pthread_mutex_lock(&ctx->log_queue.lock);

    if (ctx->log_queue.count > 0)
    {
        msg = ctx->log_queue.messages[ctx->log_queue.tl];
        ctx->log_queue.messages[ctx->log_queue.tl] = NULL;
        ctx->log_queue.tl = (ctx->log_queue.tl + 1) % LOG_Q_SZ;
        ctx->log_queue.count--;
    }

    pthread_mutex_unlock(&ctx->log_queue.lock);
    return msg;
}

/**
 * Logger thread function that writes messages from the log queue
 * 
 * This function processes messages from the log queue and writes them
 * to the configured log file. With arena-based memory management,
 * we no longer need to free individual message strings.
 *
 * @param arg       Pointer to agent_context_t cast as void*
 * @return          NULL on thread completion
 */
void *log_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;

    while (1)
    {
        pthread_mutex_lock(&ctx->log_queue.lock);

        /* Should we exit? */
        if (!ctx->log_queue.running && ctx->log_queue.count == 0)
        {
            pthread_mutex_unlock(&ctx->log_queue.lock);
            break;
        }

        /* Wait for messages when q is empty */
        while (ctx->log_queue.running && ctx->log_queue.count == 0)
            pthread_cond_wait(&ctx->log_queue.cond, &ctx->log_queue.lock);

        if (ctx->log_queue.count > 0)
        {
            char *msg = ctx->log_queue.messages[ctx->log_queue.tl];
            ctx->log_queue.messages[ctx->log_queue.tl] = NULL;
            ctx->log_queue.tl = (ctx->log_queue.tl + 1) % LOG_Q_SZ;
            ctx->log_queue.count--;
            pthread_mutex_unlock(&ctx->log_queue.lock);

            /* We assume that messages have a trailing new line here - we could check and add if missing */
            fprintf(ctx->log_file, "%s", msg);
            fflush(ctx->log_file);
        }
        else /* Nothing to do so release lock */
            pthread_mutex_unlock(&ctx->log_queue.lock);    
    }

    return NULL;
}

int start_thread(pthread_t *thread, thread_fn *fun, char *name, agent_context_t *ctx)
{
    int err = 0;
    err = pthread_create(thread, NULL, fun, ctx);
    if (err != 0)
    {
        printf("ERROR: Failed to start %s thread: %d\n", name, err);
        return 1;
    }

    err = pthread_detach(*thread);
    if (err != 0)
    {
        printf("ERROR: Failed to detach %s thread: %d\n", name, err);
        return 1;
    }
    return 0;
}

void cleanup_log_system(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->log_queue.lock);
    ctx->log_queue.running = 0;
    pthread_cond_broadcast(&ctx->log_queue.cond);
    pthread_mutex_unlock(&ctx->log_queue.lock);

    /* Create a joinable copy of the thread */
    pthread_t log_thread_copy = ctx->log_thread;
    
    /* Make thread joinable */
    pthread_detach(ctx->log_thread);
    
    /* Wait for thread to terminate */
    int join_result = safe_thread_join(log_thread_copy, 2);
    if (join_result != 0) 
    {
        /* If thread didn't terminate in time, proceed anyway */
        fprintf(stderr, "WARNING: Log thread did not terminate within timeout\n");
    }

    /* Purge remaining messages */
    char *msg;
    while ((msg = log_deq(ctx)) != NULL)
    {
        fprintf(ctx->log_file, "%s\n", msg);
    }

    if (ctx->log_file != stdout && ctx->log_file != stderr)
        fclose(ctx->log_file);

    pthread_cond_destroy(&ctx->log_queue.cond);
    pthread_mutex_destroy(&ctx->log_queue.lock);
}

void init_samples(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        ctx->full_samples[i].signature = NULL;
        ctx->full_samples[i].entry_count = 0;
        ctx->full_samples[i].exit_count = 0;
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        ctx->nth_samples[i].signature = NULL;
        ctx->nth_samples[i].entry_count = 0;
        ctx->nth_samples[i].exit_count = 0;
    }
}

void cleanup_samples(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        ctx->full_samples[i].signature = NULL;
        ctx->full_samples[i].entry_count = 0;
        ctx->full_samples[i].exit_count = 0;
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        
        ctx->nth_samples[i].signature = NULL;
        ctx->nth_samples[i].entry_count = 0;
        ctx->nth_samples[i].exit_count = 0;
        
    }
    ctx->full_hd = ctx->full_count = ctx->nth_hd = ctx->nth_count = 0;
}

int init_event_q(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    ctx->event_queue.hd = 0;
    ctx->event_queue.tl = 0;
    ctx->event_queue.count = 0;
    ctx->event_queue.running = 1;
    int err = 0;

    err = pthread_mutex_init(&ctx->event_queue.lock, NULL);
    if (err != 0)
    {
        LOG(ctx, "ERROR: Failed to init event q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&ctx->event_queue.cond, NULL);
    if (err != 0)
    {
        LOG(ctx, "ERROR: Failed to init event q condition: %d\n", err);
        return 1;
    }

    return 0;
}

void event_enq(agent_context_t *ctx, const char *class_sig, const char *method_name, const char *method_sig, int is_entry)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->event_queue.lock);

    arena_t *arena = find_arena(ctx->arena_head, "event_arena");
    if (ctx->event_queue.count < EVENT_Q_SZ)
    {
        trace_event_t *e = &ctx->event_queue.events[ctx->event_queue.hd];
        e->class_sig = arena_strdup(arena, class_sig);
        e->method_name = arena_strdup(arena, method_name);
        e->method_sig = arena_strdup(arena, method_sig);
        e->is_entry = is_entry;

        if (!e->class_sig || !e->method_name || !e->method_sig) 
        {
            LOG(ctx, "ERROR: Failed to allocate event strings");
            e->class_sig = e->method_name = e->method_sig = NULL;
        } 
        else 
        {
            ctx->event_queue.hd = (ctx->event_queue.hd + 1) % EVENT_Q_SZ;
            ctx->event_queue.count++;
            pthread_cond_signal(&ctx->event_queue.cond);
        }
    }
    else
        LOG(ctx, "WARNING: Event queue full, dropping event for %s %s %s", class_sig, method_name, method_sig);

    pthread_mutex_unlock(&ctx->event_queue.lock);
}

int event_deq(agent_context_t *ctx, trace_event_t *e)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->event_queue.lock);

    if (ctx->event_queue.count > 0)
    {
        *e = ctx->event_queue.events[ctx->event_queue.tl];
        ctx->event_queue.tl = (ctx->event_queue.tl + 1) % EVENT_Q_SZ;
        ctx->event_queue.count--;
        pthread_mutex_unlock(&ctx->event_queue.lock);
        return 1;
    }

    pthread_mutex_unlock(&ctx->event_queue.lock);
    return 0;
}

void *event_thread_func(void *arg)
{
    assert(arg != NULL);

    trace_event_t e;
    agent_context_t *ctx = (agent_context_t *)arg;
    
    arena_t *event_arena = find_arena(ctx->arena_head, "event_arena");
    arena_t *sample_arena = find_arena(ctx->arena_head, "sample_arena");

    while (1)
    {
        pthread_mutex_lock(&ctx->event_queue.lock);

        if (!ctx->event_queue.running && ctx->event_queue.count == 0)
        {
            pthread_mutex_unlock(&ctx->event_queue.lock);
            break;
        }

        while (ctx->event_queue.running && ctx->event_queue.count == 0)
            pthread_cond_wait(&ctx->event_queue.cond, &ctx->event_queue.lock);

        /* Process an event if available */
        if (ctx->event_queue.count > 0)
        {
            e = ctx->event_queue.events[ctx->event_queue.tl];
            ctx->event_queue.tl = (ctx->event_queue.tl + 1) % EVENT_Q_SZ;
            ctx->event_queue.count--;
            pthread_mutex_unlock(&ctx->event_queue.lock);

            /* Now we copy the sig/method strings */
            char full_sig[MAX_SIG_SZ];
            
            int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", e.class_sig, e.method_name, e.method_sig);
            if (written < 0 || written >= MAX_SIG_SZ)
                LOG(ctx, "WARNING: Full signature truncated: %s %s %s", e.class_sig, e.method_name, e.method_sig);
            
            /* Grab a lock before updating samples */
            pthread_mutex_lock(&ctx->samples_lock);

            /* Check if this method is already contained in full_samples */
            int found_in_full_samples = 0;
            for (int i=0; i < ctx->full_count; i++)
            {
                int idx = (ctx->full_hd + i) % FULL_SAMPLE_SZ;
                if (ctx->full_samples[idx].signature && strcmp(ctx->full_samples[idx].signature, full_sig) == 0)
                {
                    /* Update an existing sample with entry/exit count */
                    e.is_entry ? ctx->full_samples[idx].entry_count++ : ctx->full_samples[idx].exit_count++;
                    found_in_full_samples = 1;
                    break;
                }
            }

            /* We did't find the signature in full_samples so add it here */
            if (!found_in_full_samples)
            {
                if (ctx->full_count < FULL_SAMPLE_SZ)
                {
                    /* Copy the full_sig value to the samples signature as full_sig is a stack allocated buffer */
                    ctx->full_samples[ctx->full_count].signature = arena_strdup(event_arena, full_sig);
                    /* Set correct info for exit/entry */
                    ctx->full_samples[ctx->full_count].entry_count = e.is_entry ? 1 : 0;
                    ctx->full_samples[ctx->full_count].exit_count = e.is_entry ? 0 : 1;
                    ctx->full_count++;
                }
                else /* We have FULL_SAMPLE_SZ number of samples already */
                {
                    /* Set our index to the current hd */
                    int idx = ctx->full_hd;
                    /* Set the signature to the new value */
                    ctx->full_samples[idx].signature = arena_strdup(sample_arena, full_sig);
                    /* Set correct info for exit/entry */
                    ctx->full_samples[idx].entry_count = e.is_entry ? 1 : 0;
                    ctx->full_samples[idx].exit_count = e.is_entry ? 0 : 1;
                    /* Reset the full_hd position */
                    ctx->full_hd = (ctx->full_hd + 1) % FULL_SAMPLE_SZ;
                }
            }

            /* Handle nth sample collection (every ctx->config.rate events) */
            ctx->event_counter++;
            if (ctx->event_counter % ctx->config.rate == 0)
            {
                /* Check if this method signature is already in the nth samples */
                int found_in_nth_samples = 0;
                for (int i = 0; i < ctx->nth_count; i++)
                {
                    int idx = (ctx->nth_hd + i) % NTH_SAMPLE_SZ;
                    if (ctx->nth_samples[idx].signature && strcmp(ctx->nth_samples[idx].signature, full_sig) == 0)
                    {
                        /* Update the existing sample with entry/exit count */
                        e.is_entry ? ctx->nth_samples[idx].entry_count++ : ctx->nth_samples[idx].exit_count++;
                        found_in_nth_samples = 1;
                        break;
                    }
                }

                if (!found_in_nth_samples)
                {
                    /* Add to nth_samples if we cannot find method signature */
                    if (ctx->nth_count < NTH_SAMPLE_SZ)
                    {
                        ctx->nth_samples[ctx->nth_count].signature = arena_strdup(sample_arena, full_sig);
                        ctx->nth_samples[ctx->nth_count].entry_count = e.is_entry ? 1 : 0;
                        ctx->nth_samples[ctx->nth_count].exit_count = e.is_entry ? 0 : 1;
                        ctx->nth_count++;
                    }
                    else /* Replace the oldest entry */
                    {
                        int idx = ctx->nth_hd;
                        ctx->nth_samples[idx].signature = arena_strdup(sample_arena, full_sig);
                        ctx->nth_samples[idx].entry_count = e.is_entry ? 1 : 0;
                        ctx->nth_samples[idx].exit_count = e.is_entry ? 0 : 1;
                        ctx->nth_hd = (ctx->nth_hd + 1) % NTH_SAMPLE_SZ;
                    }
                }
            }

            /* Unlock the samples lock now we've finished updating */
            pthread_mutex_unlock(&ctx->samples_lock);

            continue;
        }        
        pthread_mutex_unlock(&ctx->event_queue.lock);
    }
    return NULL;
}

/**
 * Properly shut down the event system and wait for thread termination
 *
 * This function signals threads to terminate, waits for them to complete,
 * and then cleans up resources.
 *
 * @param ctx       Pointer to the agent context
 */
void cleanup_event_system(agent_context_t *ctx)
{
    assert(ctx != NULL);

    pthread_mutex_lock(&ctx->event_queue.lock);
    ctx->event_queue.running = 0;
    pthread_cond_broadcast(&ctx->event_queue.cond);
    pthread_mutex_unlock(&ctx->event_queue.lock);

    /* TODO Purge remaining events
    Not sure this is required
    while (dequeue_event(&event))

    */

    /* Create a joinable copy of the thread */
    pthread_t event_thread_copy = ctx->event_thread;

    /* Wait for thread to terminate */
    int join_result = safe_thread_join(event_thread_copy, 2);
    if (join_result != 0) {
        /* If thread didn't terminate in time, we'll proceed with cleanup anyway
          Not much we can do at this point */
        LOG(ctx, "WARNING: Event thread did not terminate within timeout\n");
    }

    /* Now that the thread is either terminated or detached, we can clean up */
    cleanup_samples(ctx);

    // /* Destroy the event_arena which will cleanup any allocated strings */
    // arena_t *arena = find_arena(ctx->arena_head, "event_arena");
    // if (arena)
    // {
    //     arena_destroy(arena);
    //     arena = NULL;
    // }

    pthread_cond_destroy(&ctx->event_queue.cond);
    pthread_mutex_destroy(&ctx->event_queue.lock);
}

void export_to_file(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    FILE *fp = fopen(ctx->config.sample_file_path, "w");
    if (!fp) 
    {
        LOG(ctx, "ERROR: Failed to open sample file: %s\n", ctx->config.sample_file_path);
        return;
    }

    pthread_mutex_lock(&ctx->samples_lock);
    fprintf(fp, "# Full Samples (every event)\n");
    for (int i = 0; i < ctx->full_count; i++) {
        int idx = (ctx->full_hd + i) % FULL_SAMPLE_SZ;
        LOG(ctx, "%d full sample for sig %s\n", idx, ctx->full_samples[idx].signature);
        if (ctx->full_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    ctx->full_samples[idx].signature, 
                    ctx->full_samples[idx].entry_count, 
                    ctx->full_samples[idx].exit_count);
        }
    }
    fprintf(fp, "# Nth Samples (every %d events)\n", ctx->config.rate);
    for (int i = 0; i < ctx->nth_count; i++) {
        int idx = (ctx->nth_hd + i) % NTH_SAMPLE_SZ;
        LOG(ctx, "%d nth sample for sig %s\n", idx, ctx->nth_samples[idx].signature);
        if (ctx->nth_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    ctx->nth_samples[idx].signature, 
                    ctx->nth_samples[idx].entry_count, 
                    ctx->nth_samples[idx].exit_count);
        }
    }
    pthread_mutex_unlock(&ctx->samples_lock);

    fclose(fp);
}

void *export_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;
    
    /* Reuse event_queue.running as a global stop flag */
    while (ctx->event_queue.running) 
    { 
        export_to_file(ctx);
        sleep(ctx->config.export_interval);
    }

    /* Final write on shutdown */
    export_to_file(ctx); 
    return NULL;
}
/**
 * get a param value for a method
 * 
 */
static char *get_parameter_value(arena_t *arena, jvmtiEnv *jvmti, JNIEnv *jni_env, 
    jthread thread, jmethodID method, jint param_index, jint param_slot, char param_type)
{
    char *result = NULL;
    jvalue value;
    jvmtiError err;

    switch(param_type)
    {
        /* int */
        case 'I':
            err = (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
            if (err == JVMTI_ERROR_NONE)
            {
                /* Allocate space for result (max int digist + sign + null) */
                result = arena_alloc(arena, 12);
                if (result)
                    sprintf(result, "%d", value.i);
            }
            break;

        /* long */
        case 'J':
            err = (*jvmti)->GetLocalLong(jvmti, thread, 0, param_slot, &value.j);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(arena, 21);
                if (result)
                    sprintf(result, "%lld", (long long)value.j);
            }
            break;

        /* float */
        case 'F':
            err = (*jvmti)->GetLocalFloat(jvmti, thread, 0, param_slot, &value.f);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(arena, 32);
                if (result)
                    sprintf(result, "%f", value.f);
            }
            break;

        /* double */
        case 'D':
            err = (*jvmti)->GetLocalDouble(jvmti, thread, 0, param_slot, &value.d);
            if (err == JVMTI_ERROR_NONE)
            {
                /* TODO check this as it's the same size as a float?? */
                result = arena_alloc(arena, 32);
                if (result)
                    sprintf(result, "%f", value.d);
            }
            break;

        /* boolean */
        case 'Z':
            err = (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(arena, 6);
                if (result)
                    sprintf(result, "%s", value.i ? "true" : "false");
            }
            break;

        case 'B': /* byte */
        case 'C': /* char */
        case 'S': /* short */
            err = (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(arena, 12);
                if (result)
                    sprintf(result, "%d", value.i);
            }
            break;

        case 'L': /* Object */
        case '[': /* Array */
            {
                jobject obj;
                err = (*jvmti)->GetLocalObject(jvmti, thread, 0, param_slot, &obj);
                if (err == JVMTI_ERROR_NONE && obj != NULL)
                {
                    jstring str;
                    jclass str_class = (*jni_env)->FindClass(jni_env, "java/lang/String");
                    /* We have a string */
                    if ((*jni_env)->IsInstanceOf(jni_env, obj, str_class))
                    {
                        const char *str_value = (*jni_env)->GetStringUTFChars(jni_env, obj, NULL);
                        if (str_value)
                        {
                            result = arena_alloc(arena, strlen(str_value) + 3); /* includes quotes and null */
                            if (result)
                                sprintf(result, "\"%s\"", str_value);
                            
                            (*jni_env)->ReleaseStringUTFChars(jni_env, obj, str_value);
                        }
                    }
                    else /* Non-string object */
                    {
                        jclass obj_class = (*jni_env)->GetObjectClass(jni_env, obj);
                        jmethodID toString_method = (*jni_env)->GetMethodID(jni_env, obj_class, "toString", "()Ljava/lang/String;");
                        str = (jstring)(*jni_env)->CallObjectMethod(jni_env, obj, toString_method);

                        if (str != NULL)
                        {
                            const char *str_value = (*jni_env)->GetStringUTFChars(jni_env, str, NULL);
                            if (str_value)
                            {
                                result = arena_alloc(arena, strlen(str_value) + 1);
                                if (result)
                                    strcpy(result, str_value);

                                (*jni_env)->ReleaseStringUTFChars(jni_env, str, str_value);
                            }
                        }
                        else
                        {
                            result = arena_alloc(arena, 5);
                            if (result)
                                strcpy(result, "null");
                        }
                    }
                }
                else
                {
                    result = arena_alloc(arena, 5);
                    if (result)
                        strcpy(result, "null");
                }
            }
            break;
        
        default:
            result = arena_alloc(arena, 16);
            if (result)
                sprintf(result, "<unknown type>");

            break;
    }

    if (!result)
    {
        result = arena_alloc(arena, 10);
        if (result)
            sprintf(result, "<error>");
    }

    return result;
}

/*
 * Method entry callback
 */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method)
{
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaring_class;
    jvmtiError err;

    if (jvmti != global_ctx->jvmti_env)
        LOG(global_ctx, "WARNING: jvmti (%p) differs from global_ctx->jvmti_env (%p)\n", jvmti, global_ctx->jvmti_env);

    err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetClassSignature(jvmti, declaring_class, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    /* Check if we should sample this method call */
    int sample_index = should_sample_method(global_ctx, class_signature, method_name, method_signature);

    if (sample_index > 0) {
        /* We're sampling this call */
        method_sample_t *sample = get_thread_local_sample();
        if (sample) {
            sample->method_index = sample_index - 1;  /* Convert back to 0-based index */
            sample->start_time = get_current_time_ns();
            
            /* Only collect these metrics if enabled for this method */
            unsigned int flags = global_ctx->metrics->metric_flags[sample->method_index];
            
            if (flags & METRIC_FLAG_MEMORY)
                sample->start_memory = get_current_memory();
            
            if (flags & METRIC_FLAG_CPU)
                sample->start_cpu = get_current_cpu_cycles();
            
            LOG(global_ctx, "[ENTRY] Sampling method %s.%s%s\n", 
                class_signature, method_name, method_signature);
        }
    }

deallocate:
    /* Deallocate memory allocated by JVMTI */
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_name);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_signature);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)class_signature);
}

/*
 * Method exit callback
 */
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value)
{
    method_sample_t *sample = get_thread_local_sample();
    
    /* If we're not sampling this method, return early */
    if (!sample || sample->method_index < 0)
        return;
    
    /* Calculate execution time */
    uint64_t end_time = get_current_time_ns();
    uint64_t exec_time = end_time - sample->start_time;
    
    /* Get metrics if they were enabled */
    uint64_t memory_delta = 0;
    uint64_t cpu_delta = 0;
    
    unsigned int flags = global_ctx->metrics->metric_flags[sample->method_index];
    
    if (flags & METRIC_FLAG_MEMORY) {
        uint64_t end_memory = get_current_memory();
        memory_delta = (end_memory > sample->start_memory) ? 
                      (end_memory - sample->start_memory) : 0;
    }
    
    if (flags & METRIC_FLAG_CPU) {
        uint64_t end_cpu = get_current_cpu_cycles();
        cpu_delta = end_cpu - sample->start_cpu;
    }
    
    
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaringClass;
    jvmtiError err;

    /* Get method details for logging */
    if (tls_initialized && global_ctx->metrics->metric_flags[sample->method_index] != 0) {
        /* Get method name */
        err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
            goto record_metrics;
        }

        /* Get declaring class */
        err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaringClass);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
            goto deallocate;
        }

        /* Get class signature */
        err = (*jvmti)->GetClassSignature(jvmti, declaringClass, &class_signature, NULL);
        if (err != JVMTI_ERROR_NONE)
        {
            LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
            goto deallocate;
        }
        
        LOG(global_ctx, "[EXIT] Method %s.%s%s executed in %llu ns, memory delta: %llu bytes\n", 
            class_signature, method_name, method_signature, 
            (unsigned long long)exec_time, (unsigned long long)memory_delta);
    }

record_metrics:
    /* Record the metrics */
    record_method_execution(global_ctx, sample->method_index, exec_time, memory_delta, cpu_delta);
    
    /* Reset sample for reuse */
    sample->method_index = -1;
    

deallocate:
    /* Deallocate memory allocated by JVMTI */
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_name);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_signature);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)class_signature);
}

/**
 * Exception callback
 */
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location)
{
    char *method_name = NULL;
    char *method_signature = NULL;

    /* TODO is this needed? */
    char *generic_signature = NULL;

    char *class_name = NULL;
    char *catch_method_name = NULL;
    char *catch_method_signature = NULL;
    jvmtiLocalVariableEntry *table = NULL;

    /* Get details of method */
    jvmtiError err = (*jvmti_env)->GetMethodName(
        jvmti_env, method, &method_name, &method_signature, &generic_signature);
    
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    jclass method_class;
    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &method_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }
    
    /* Get class name */
    err = (*jvmti_env)->GetClassSignature(jvmti_env, method_class, &class_name, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }
        
    /* Convert Java exception to string representation */
    jclass exception_class = (*jni_env)->GetObjectClass(jni_env, exception);
    jmethodID toString_id = (*jni_env)->GetMethodID(jni_env, exception_class, "toString", "()Ljava/lang/String;");
    jstring exception_str = (*jni_env)->CallObjectMethod(jni_env, exception, toString_id);
    if ((*jni_env)->ExceptionCheck(jni_env)) 
    {
        LOG(global_ctx, "ERROR: JNI exception occurred while getting exception string\n");
        (*jni_env)->ExceptionClear(jni_env);
        goto deallocate;
    }
    
    /* Convert to standard C string */
    const char *exception_cstr = exception_str ? (*jni_env)->GetStringUTFChars(jni_env, exception_str, NULL) : "Unknown exception";
    
    LOG(global_ctx, "Exception in %s.%s%s at location %ld\n", class_name, method_name, method_signature, (long)location);
    LOG(global_ctx, "Exception details: %s\n", exception_cstr);
    
    /* Get the local variable table for this method */
    jint entry_count = 0;
    err = (*jvmti_env)->GetLocalVariableTable(jvmti_env, method, &entry_count, &table);

    /* all other errors just bail */
    if (err != JVMTI_ERROR_NONE && err != JVMTI_ERROR_ABSENT_INFORMATION)
    {
        LOG(global_ctx, "ERROR: Could not get local variable table %d\n", err);
        goto deallocate;
    }

    /* Parse the method signature for params */
    char *params = strchr(method_signature, '(');
    if (params != NULL)
    {
        /* advance past the opening '(' */
        params++;

        /* Is this a non-static method? If so, the first variable is 'this' */
        jboolean is_static;
        (*jvmti_env)->IsMethodNative(jvmti_env, method, &is_static);

        int param_idx = 0;
        int slot = is_static ? 0 : 1; /* Start at either 0 or 1 skipping 'this' */

        LOG(global_ctx, "Method params: \n");

        arena_t *arena = find_arena(global_ctx->arena_head, "exception_arena");
        if (arena == NULL)
        {
            LOG(global_ctx, ">> Unable to find exception arena on list! <<\n");
            goto deallocate;
        }

        while (*params != ')' && *params != '\0')
        {
            char param_type = *params;
            char buffer[256] = {0};

            /* Handle obj types (find the end of the class name) */
            if (param_type == 'L')
            {
                strncpy(buffer, params, sizeof(buffer) -1);
                char *semicolon = strchr(buffer, ';');
                if (semicolon)
                {
                    *semicolon = '\0';
                    params += (semicolon - buffer);
                }
            }

            /* Find the parameter name in the local variable table */
            char *param_name = NULL;
            for (int i = 0; i < entry_count; i++)
            {
                if (table[i].slot == slot && table[i].start_location == 0)
                {
                    param_name = table[i].name;
                    break;
                }
            }
            
            /* Get the param value */
            char *param_val = get_parameter_value(arena, jvmti_env, jni_env, thread, method, param_idx, slot, param_type);

            LOG(global_ctx, "\tParam %d (%s): %s\n", 
                param_idx, 
                param_name ? param_name : "<unknown>",
                param_val ? param_val : "<error>");

            if (param_val)
                arena_free(arena, param_val);
            
            slot++;
            param_idx++;

            /* For long and double values they require two slots so advance a second time */
            if (param_type == 'J' || param_type == 'D')
                slot++;

            /* Next param */
            params++;
        }
    }

    /* Free the local variable table */
    for (int i = 0; i < entry_count; i++)
    {
        (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)table[i].name);
        (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)table[i].signature);
        (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)table[i].generic_signature);
    }

    /* Only try to deallocate with a valid pointer */
    if (table)
        (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)table);
        
    /* check the catch method */
    if (catch_method != NULL) 
    {
        
        err = (*jvmti_env)->GetMethodName(jvmti_env, catch_method, &catch_method_name, &catch_method_signature, NULL);

        if (err != JVMTI_ERROR_NONE)
        {
            LOG(global_ctx, "ERROR: GetMethodName for catch_method failed with error %d\n", err);
            goto deallocate;
        }
        
        LOG(global_ctx, "Caught in method: %s%s at location %ld\n", catch_method_name, catch_method_signature, (long)catch_location);
    }

    /* Free exception_str */
    (*jni_env)->ReleaseStringUTFChars(jni_env, exception_str, exception_cstr);   

deallocate:
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_signature);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)generic_signature);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)catch_method_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)catch_method_signature);
}

/**
 * Load agent configuration from a file
 * 
 * Uses arena-based memory management for all string operations.
 * Parses the new format for method signature filters that includes
 * per-method sampling rates and metrics to collect.
 * 
 * @param ctx       Pointer to agent context
 * @param cf        Path to config file, or NULL to use default
 * @return          0 on success, 1 on failure
 */
int load_config(agent_context_t *ctx, const char *cf)
{
    assert(ctx != NULL);
    
    int res = 0;
    
    if (ctx == NULL) 
        return 1;
    
    LOG(ctx, "INFO: loading config from: %s, default config_file: %s\n", cf, DEFAULT_CFG_FILE);
    if (!cf) 
        cf = DEFAULT_CFG_FILE;
    
    FILE *fp = fopen(cf, "r");
    if (!fp) 
    {
        LOG(ctx, "ERROR: Could not open config file: %s\n", cf);
        return 1;
    }
    
    char line[256];
    char *current_section = NULL;
    
    arena_t *arena = find_arena(ctx->arena_head, "config_arena");

    while (fgets(line, sizeof(line), fp))
    {
        /* Process the line (strip comments, trim whitespace) */
        char *processed = arena_process_config_line(arena, line);
        if (!processed || processed[0] == '\0')
            continue;  /* Skip empty lines */
        
        /* Handle section headers */
        if (processed[0] == '[')
        {
            current_section = processed;  /* Just point to the arena-allocated string */
            continue;
        }
        
        /* Skip any data before the first section */
        if (!current_section)
            continue;
        
        /* Based on the section we're in, interpret the value differently */
        if (strcmp(current_section, "[method_signatures]") == 0)
        {
            LOG(ctx, "DEBUG: Processing line in [method_signatures]: '%s'\n", processed);
            /* Skip over the filters line, end of filters is a line containing a single ']' */
            if (strncmp(processed, "filters =", 9) == 0 || processed[0] == ']')
                continue;
            
            /* Process a filter entry in the new format: 
               class_signature:method_name:method_signature:sample_rate:metrics */
            char class_sig[MAX_SIG_SZ], method_name[MAX_SIG_SZ], method_sig[MAX_SIG_SZ];
            int sample_rate;
            char metrics[MAX_SIG_SZ] = {0};
            
            /* Initialize with default values */
            strcpy(method_name, "*");        /* Default to wildcard method */
            strcpy(method_sig, "*");         /* Default to wildcard signature */
            sample_rate = ctx->config.rate;  /* Default to global rate */
            
            /* Try to parse with the new format first */
            int parsed = sscanf(processed, "%[^:]:%[^:]:%[^:]:%d:%s", 
                              class_sig, method_name, method_sig, &sample_rate, metrics);
            
            /* Handle partially specified entries */
            if (parsed < 1) 
            {
                LOG(ctx, "ERROR: Invalid method filter format: %s\n", processed);
                continue;
            }
            
            /* Build the full signature for matching */
            char full_sig[MAX_SIG_SZ * 3];
            snprintf(full_sig, sizeof(full_sig), "%s %s %s", class_sig, method_name, method_sig);
            
            /* Determine which metrics to collect */
            unsigned int metric_flags = 0;
            if (parsed >= 5) 
            {
                if (strstr(metrics, "time"))   metric_flags |= METRIC_FLAG_TIME;
                if (strstr(metrics, "memory")) metric_flags |= METRIC_FLAG_MEMORY;
                if (strstr(metrics, "cpu"))    metric_flags |= METRIC_FLAG_CPU;
            } 
            else 
            {
                /* Default to collecting time if not specified */
                metric_flags = METRIC_FLAG_TIME;
            }
            
            /* Add to metrics SoA structure */
            int method_index = add_method_to_metrics(ctx, full_sig, sample_rate, metric_flags);
            if (method_index < 0) {
                LOG(ctx, "ERROR: Failed to add method filter: %s\n", full_sig);
                continue;
            }
            
            LOG(ctx, "DEBUG: Added method filter #%d: '%s' with rate=%d\n", 
                method_index, full_sig, sample_rate);
            
            /* Keep track of the number of filters */
            ctx->config.num_filters++;
        }
        else
        {
            /* Extract and trim the value part */
            char *value = arena_extract_and_trim_value(arena, processed);
            if (!value)
                continue;
            
            if (strcmp(current_section, "[sample_rate]") == 0)
            {
                /* This is now the default/global sample rate */
                int rate;
                if (sscanf(value, "%d", &rate) == 1)
                    ctx->config.rate = rate > 0 ? rate : 1;
            }
            else if (strcmp(current_section, "[sample_file_location]") == 0)
            {
                /* Store the arena-allocated string directly */
                ctx->config.sample_file_path = value;
            }
            else if (strcmp(current_section, "[export]") == 0)
            {
                if (strstr(processed, "method"))
                {
                    /* Store the arena-allocated string directly */
                    ctx->config.export_method = value;
                }
                else if (strstr(processed, "interval"))
                {
                    if (sscanf(value, "%d", &ctx->config.export_interval) != 1)
                        LOG(ctx, "WARNING: Invalid interval value: %s\n", value);
                }
            }
        }
    }
    
    fclose(fp);
    
    /* Set defaults if needed */
    if (!ctx->config.export_method) 
    {
        ctx->config.export_method = arena_strdup(arena, "file");
        if (!ctx->config.export_method)
            LOG(ctx, "ERROR: Failed to set default export_method\n");
    }
    
    LOG(ctx, "Config loaded: default_rate=%d, filters=%d, path=%s, method=%s\n",
        ctx->config.rate, ctx->config.num_filters,
        ctx->config.sample_file_path ? ctx->config.sample_file_path : "NULL",
        ctx->config.export_method ? ctx->config.export_method : "NULL");
    
    return res;
}

/**
 * Helper function to initialize the metrics Struct-of-Arrays structure
 */
method_metrics_soa_t *init_method_metrics(arena_t *arena, size_t initial_capacity) {
    method_metrics_soa_t *metrics = arena_alloc(arena, sizeof(method_metrics_soa_t));
    if (!metrics) return NULL;
    
    metrics->capacity = initial_capacity;
    metrics->count = 0;
    
    /* Allocate all arrays */
    metrics->signatures = arena_alloc(arena, initial_capacity * sizeof(char*));
    metrics->sample_rates = arena_alloc(arena, initial_capacity * sizeof(int));
    metrics->call_counts = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->sample_counts = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->total_time_ns = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->min_time_ns = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->max_time_ns = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->alloc_bytes = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->peak_memory = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->cpu_cycles = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    metrics->metric_flags = arena_alloc(arena, initial_capacity * sizeof(unsigned int));
    
    /* Check if all allocations succeeded */
    if (!metrics->signatures || !metrics->sample_rates || !metrics->call_counts ||
        !metrics->sample_counts || !metrics->total_time_ns || !metrics->min_time_ns ||
        !metrics->max_time_ns || !metrics->alloc_bytes || !metrics->peak_memory ||
        !metrics->cpu_cycles || !metrics->metric_flags) {
        return NULL;
    }
    
    /* Initialize arrays with zeros */
    memset(metrics->sample_rates, 0, initial_capacity * sizeof(int));
    memset(metrics->call_counts, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->sample_counts, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->total_time_ns, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->min_time_ns, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->max_time_ns, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->alloc_bytes, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->peak_memory, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->cpu_cycles, 0, initial_capacity * sizeof(uint64_t));
    memset(metrics->metric_flags, 0, initial_capacity * sizeof(unsigned int));
    
    /* Set min_time_ns to maximum value initially */
    for (size_t i = 0; i < initial_capacity; i++) {
        metrics->min_time_ns[i] = UINT64_MAX;
    }
    
    return metrics;
}

/**
 * Add a method to the metrics structure
 */
int add_method_to_metrics(agent_context_t *ctx, const char *signature, int sample_rate, unsigned int flags) {
    method_metrics_soa_t *metrics = ctx->metrics;
    
    assert(ctx != NULL);
    assert(ctx->metrics != NULL);

    /* Check if method already exists */
    int index = find_method_index(metrics, signature);
    if (index >= 0) 
    {
        /* Update existing entry */
        metrics->sample_rates[index] = sample_rate;
        metrics->metric_flags[index] = flags;
        return index;
    }
    
    /* Need to add a new entry */
    if (metrics->count >= metrics->capacity) 
    {
        /* Cannot grow in the current implementation with arenas */
        LOG(ctx, "ERROR: Method metrics capacity reached (%zu)\n", metrics->capacity);
        return -1;
    }
    
    /* Add new entry */
    arena_t *arena = find_arena(ctx->arena_head, "metrics_arena"); 
    index = metrics->count;
    metrics->signatures[index] = arena_strdup(arena, signature);
    metrics->sample_rates[index] = sample_rate;
    metrics->call_counts[index] = 0;
    metrics->sample_counts[index] = 0;
    metrics->total_time_ns[index] = 0;
    metrics->min_time_ns[index] = UINT64_MAX;
    metrics->max_time_ns[index] = 0;
    metrics->alloc_bytes[index] = 0;
    metrics->peak_memory[index] = 0;
    metrics->cpu_cycles[index] = 0;
    metrics->metric_flags[index] = flags;
    
    metrics->count++;
    return index;
}

/**
 * Find the index of a method in the metrics structure
 */
int find_method_index(method_metrics_soa_t *metrics, const char *signature) {
    if (!metrics || !signature) return -1;
    
    for (size_t i = 0; i < metrics->count; i++) {
        if (metrics->signatures[i] && strcmp(metrics->signatures[i], signature) == 0) {
            return (int)i;
        }
    }
    
    return -1;  /* Not found */
}

/**
 * Check if a method should be sampled and return its index if it should
 */
int should_sample_method(agent_context_t *ctx, const char *class_signature, 
                         const char *method_name, const char *method_signature) {
    /* We need to find the method in our metrics structure */
    char full_sig[MAX_SIG_SZ];
    int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", 
                        class_signature, method_name, method_signature);
    
    if (written < 0 || written >= MAX_SIG_SZ) {
        /* Signature is too long, skip */
        return 0;
    }
    
    int method_index = find_method_index(ctx->metrics, full_sig);
    
    /* If exact match not found, try class wildcard */
    if (method_index < 0) {
        written = snprintf(full_sig, sizeof(full_sig), "%s * *", class_signature);
        if (written >= 0 && written < MAX_SIG_SZ) {
            method_index = find_method_index(ctx->metrics, full_sig);
        }
    }
    
    /* If still not found, not a method we want to sample */
    if (method_index < 0) {
        return 0;
    }
    
    /* We found the method, increment its call count */
    ctx->metrics->call_counts[method_index]++;
    
    /* Check if we should sample this call based on the sample rate */
    if (ctx->metrics->call_counts[method_index] % ctx->metrics->sample_rates[method_index] == 0) {
        return method_index + 1;  /* +1 because 0 means "don't sample" */
    }
    
    return 0;  /* Don't sample this call */
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    jvmtiCapabilities capabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError err;

    /* Allocate and initialize the agent context */
    global_ctx = malloc(sizeof(agent_context_t));
    if (!global_ctx) {
        printf("ERROR: Failed to allocate agent context\n");
        return JNI_ERR;
    }
    memset(global_ctx, 0, sizeof(agent_context_t));
    global_ctx->jvmti_env = NULL;
    global_ctx->method_filters = NULL;
    global_ctx->num_filters = 0;
    global_ctx->log_file = NULL;
    global_ctx->config.rate = 1;
    global_ctx->config.filters = NULL;
    global_ctx->config.num_filters = 0;
    global_ctx->config.sample_file_path = NULL;
    global_ctx->config.export_method = NULL;
    global_ctx->config.export_interval = 60;
    global_ctx->metrics = NULL;
    global_ctx->arena_head = NULL;
    global_ctx->arena_tail = NULL;
    pthread_mutex_init(&global_ctx->samples_lock, NULL);

    /* 
      We initialise all the arenas we need in this function and we
      destroy all the arenas in the corresponding Agent_OnUnload
    */

    /* TODO use a loop here... */
    arena_t *exception_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "exception_arena", EXCEPTION_ARENA_SZ, EXCEPTION_ARENA_BLOCKS);
    if (!exception_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create exception arena\n");
        return JNI_ERR;
    }

    arena_t *log_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
    if (!log_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create log arena\n");
        return JNI_ERR;
    }

    arena_t *event_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "event_arena", EVENT_ARENA_SZ, EVENT_ARENA_BLOCKS);
    if (!event_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create event arena\n");
        return JNI_ERR;
    }

    arena_t *sample_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "sample_arena", SAMPLE_ARENA_SZ, SAMPLE_ARENA_BLOCKS);
    if (!sample_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create sample arena\n");
        return JNI_ERR;
    }

    arena_t *config_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
    if (!config_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create config arena\n");
        return JNI_ERR;
    }

    arena_t *metrics_arena = create_arena(&global_ctx->arena_head, &global_ctx->arena_tail, "metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
    if (!metrics_arena)
    {
        LOG(global_ctx, "ERROR: Failed to create metrics arena\n");
        return JNI_ERR;
    }

    size_t initial_capacity = 256;
    global_ctx->metrics = init_method_metrics(metrics_arena, initial_capacity);
    if (!global_ctx->metrics) {
        LOG(global_ctx, "ERROR: Failed to initialize metrics structure\n");
        return JNI_ERR;
    }

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || global_ctx->jvmti_env == NULL) 
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    /* Init logging */
    if (init_log_q(global_ctx) != 0)
    {
        cleanup(global_ctx);
        return JNI_ERR;
    }
    if (start_thread(&global_ctx->log_thread, &log_thread_func, "log", global_ctx) != 0)
    {
        cleanup(global_ctx);
        cleanup_log_system(global_ctx);
        return JNI_ERR;
    }

    /* Redirect output */
    if (options && strncmp(options, "logfile=", 8) == 0)
    {
        global_ctx->log_file = fopen(options + 8, "w");
        if (!global_ctx->log_file)
        {
            printf("ERROR: Failed to open log file: %s, reverting to stdout\n", options + 8);
            global_ctx->log_file = stdout;
        }
    }

    /* Now we have logging configured, load config */
    if (load_config(global_ctx, "./trace.ini") != 0)
    {
        LOG(global_ctx, "ERROR: Unable to load config_file!\n");
        return JNI_ERR;
    }

    LOG(global_ctx, "Config: rate=%d, method='%s', path='%s'\n",
        global_ctx->config.rate, global_ctx->config.export_method, global_ctx->config.sample_file_path);

    if (strcmp(global_ctx->config.export_method, "file") != 0)
    {
        LOG(global_ctx, "ERROR: Unknown export method: [%s]", global_ctx->config.export_method);
        return JNI_ERR;
    }

    /* Init the event/sample handling */
    if (init_event_q(global_ctx) != 0 || 
        start_thread(&global_ctx->event_thread, &event_thread_func, "event", global_ctx) != 0 || 
        start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != 0)
    {
        cleanup(global_ctx);
        cleanup_log_system(global_ctx);
        cleanup_event_system(global_ctx);
        return JNI_ERR;
    }

    init_samples(global_ctx);

    /* Enable capabilities */
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_method_entry_events = 1;
    capabilities.can_generate_method_exit_events = 1;
    capabilities.can_generate_exception_events = 1;
    capabilities.can_access_local_variables = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;

    err = (*global_ctx->jvmti_env)->AddCapabilities(global_ctx->jvmti_env, &capabilities);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: AddCapabilities failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;
    callbacks.Exception = &exception_callback;

    err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: SetEventCallbacks failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Enable event notifications */
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return JNI_ERR;
    }

    LOG(global_ctx, "JVMTI Agent Loaded.\n");
    return JNI_OK;
}

/**
 * Cleanup state
 * 
 * @param nf num filters to clear
 */
void cleanup(agent_context_t *ctx)
{
    /* check if we have work to do */
    if (ctx->config.filters) 
    {
        /* Only free the array of pointers, strings are handled by config_arena */
        free(ctx->config.filters);
    }

    /* Reset config values (no need to free arena allocated strings) */
    ctx->config.filters = NULL;
    ctx->config.num_filters = 0;
    ctx->config.sample_file_path = NULL;
    ctx->config.export_method = NULL;
    ctx->method_filters = NULL;
    ctx->num_filters = 0;
}

/**
 * JVMTI Agent Unload Function
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    if (global_ctx) 
    {
        /* Signal export thread to stop */
        pthread_mutex_lock(&global_ctx->event_queue.lock);
        global_ctx->event_queue.running = 0;
        pthread_mutex_unlock(&global_ctx->event_queue.lock);
        
        pthread_t export_thread_copy = global_ctx->export_thread;
        pthread_detach(global_ctx->export_thread);
        safe_thread_join(export_thread_copy, 2);

        cleanup(global_ctx);
        cleanup_samples(global_ctx);
        
        cleanup_event_system(global_ctx);

        /* Clean up thread-local storage */
        if (tls_initialized) 
        {
            /* Free the current thread's TLS data */
            method_sample_t *sample = pthread_getspecific(sample_key);
            if (sample) {
                free(sample);
                pthread_setspecific(sample_key, NULL);
            }
            
            /* Unfortunately, with pthreads there's no direct way to iterate and free 
               thread-local storage from all threads. It relies on thread exit handlers.
               We can at least delete the key to prevent further allocations. */
            /* Clean up TLS resources */
            pthread_key_delete(sample_key);
            tls_initialized = 0;
            
            /* Destroy the initialization mutex */
            pthread_mutex_destroy(&tls_init_mutex);
            
            /* Note: Any other thread that was using TLS will have its destructor called
               when that thread exits. If the JVM creates a lot of threads that don't exit,
               there could still be leaks. This is a limitation of the pthreads API. */
            LOG(global_ctx, "WARNING: Thread-local storage cleanup may be incomplete for threads that don't exit\n");
        }

        /* Finally shutdown logging */
        cleanup_log_system(global_ctx);

        /* Cleanup the arenas */
        destroy_all_arenas(&global_ctx->arena_head, &global_ctx->arena_tail);
        /* Null out metrics */
        global_ctx->metrics = NULL;

        /* Destroy mutex */
        pthread_mutex_destroy(&global_ctx->samples_lock);

        free(global_ctx);
        global_ctx = NULL;    
    }
    printf("JVMTI Agent Unloaded.\n");
}