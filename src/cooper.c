/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "arena.h"
#include "arena_str.h"
#include "log.h"

static agent_context_t *global_ctx = NULL; /* Single global context */

/* Thread-local storage key and initialization mutex */
static pthread_key_t context_key;
static int tls_initialized = 0;
static pthread_mutex_t tls_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Arena configurations */
static const arena_config_t arena_configs[] = {
    {"exception_arena", EXCEPTION_ARENA_SZ, EXCEPTION_ARENA_BLOCKS},
    {"log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS},
    {"sample_arena", SAMPLE_ARENA_SZ, SAMPLE_ARENA_BLOCKS},
    {"config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS},
    {"metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS}
};

/* Debug function for dumping method satck */
static void debug_dump_method_stack(agent_context_t *ctx, thread_context_t *tc)
{
    if (!ctx || !tc) return;

    LOG_DEBUG("Method stack dump (depth=%d):\n", tc->stack_depth);

    method_sample_t *current = tc->sample;
    int level = 0;

    while (current && level < 20) /* Have a depth cutoff */
    {
        /* Get method details */
        char *method_name = NULL;
        char *method_sig = NULL;

        jvmtiError err = (*ctx->jvmti_env)->GetMethodName(ctx->jvmti_env, current->method_id, &method_name, &method_sig, NULL);
        if (err == JVMTI_ERROR_NONE)
        {
            LOG_DEBUG("\t[%d] methodID=%p, index=%d, name=%s%s\n", 
                level, current->method_id, current->method_index, 
                method_name, method_sig);
                
            (*ctx->jvmti_env)->Deallocate(ctx->jvmti_env, (unsigned char*)method_name);
            (*ctx->jvmti_env)->Deallocate(ctx->jvmti_env, (unsigned char*)method_sig);
        }
        else
            LOG_DEBUG("\t[%d] methodID=%p, index=%d, <name-error>\n", level, current->method_id, current->method_index);
        
        current = current->parent;
        level++;
    }
}

static void destroy_thread_context(void *data)
{
    thread_context_t *tc = (thread_context_t *)data;

    /* We can ignore cleaning up the method_samples 
    as they are arena allocated*/
    if (tc)
    {
        tc->sample = NULL;
        tc->stack_depth = 0;
        free(tc);
    }
}

/* Initialize thread-local storage */
static void init_thread_local_storage() {
    /* Double-checked locking pattern */
    if (!tls_initialized) {
        pthread_mutex_lock(&tls_init_mutex);
        if (!tls_initialized) {
            /* The 'free' function will be automatically called when a thread exits */
            pthread_key_create(&context_key, destroy_thread_context);
            tls_initialized = 1;
        }
        pthread_mutex_unlock(&tls_init_mutex);
    }
}

/* Get the thread-local sample structure */
static thread_context_t *get_thread_local_context() {
    if (!tls_initialized)
        init_thread_local_storage();
    
    thread_context_t *context = pthread_getspecific(context_key);
    if (!context) {
        /* First time this thread is accessing the key */
        // TODO fix this calloc as it is not correctly free'd later
        context = calloc(1, sizeof(thread_context_t));
        if (context) {
            context->sample = NULL;
            context->stack_depth = 0;
            pthread_setspecific(context_key, context);
        }
    }
    
    return context;
}

/* Get a native thread id for a given java vm thread */
static pid_t get_native_thread_id(jvmtiEnv *jvmti_env, JNIEnv *jni, jthread thread)
{
#ifdef __linux__
    static jclass thread_class = NULL;
    static jmethodID getId_method = NULL;
    pid_t result = 0;

    /* Cache frequently used JNI refs */
    if (thread_class == NULL)
    {
        thread_class = (*jni)->FindClass(jni, "java/lang/Thread");
        if (thread_class != NULL)
        {
            thread_class = (*jni)->NewGlobalRef(jni, thread_class);
            getId_method = (*jni)->GetMethodID(jni, thread_class, "getId", "()J");
        }
    }

    if (thread_class != NULL && getId_method != NULL)
    {
        /* Get the jvm thread id */
        jlong thread_id = (*jni)->CallLongMethod(jni, thread, getId_method);

        /* Use Thread.getId() as a key to our mapping table */
        pthread_mutex_lock(&global_ctx->samples_lock);

        /* Check for previous mapping */
        for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
        {
            if (global_ctx->thread_mappings[i].java_thread_id == thread_id)
            {
                result = global_ctx->thread_mappings[i].native_thread_id;
                pthread_mutex_unlock(&global_ctx->samples_lock);
                return result;
            }
        }

        pthread_mutex_unlock(&global_ctx->samples_lock);

        /* 
        This is a new thread id, not previously found in our mappings.
        We'll need to have the thread tell us its native ID. This part
        can only be done from within the thread itself...
        */

        if (result == 0)
        {
            /* check if current thread */
            jthread current_thread;
            (*jvmti_env)->GetCurrentThread(jvmti_env, &current_thread);
            jboolean is_same_thread = (*jni)->IsSameObject(jni, thread, current_thread);

            if (is_same_thread)
            {
                result = syscall(SYS_gettid);

                /* Add to our map */
                pthread_mutex_lock(&global_ctx->samples_lock);
                for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
                {
                    if (global_ctx->thread_mappings[i].java_thread_id == 0)
                    {
                        global_ctx->thread_mappings[i].java_thread_id = thread_id;
                        global_ctx->thread_mappings[i].native_thread_id = result;
                        break;
                    }
                }
                pthread_mutex_unlock(&global_ctx->samples_lock);
            }
        }
    }
    return result;
#else
    return 0; /* Not implemented for other platforms */
#endif
}

/* Process-wide mem tracking for linux */
static uint64_t get_process_memory()
{
#ifdef __linux__
    static int proc_fd = -1;
    static char buf[4096];

    /* init file descriptor if required */
    if (proc_fd < 0)
    {
        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/statm", getpid());
        proc_fd = open(proc_path, O_RDONLY);
        if (proc_fd < 0)
            return 0;
    }

    /* reset file position to beginning */
    if (lseek(proc_fd, 0, SEEK_SET) < 0)
        return 0;

    ssize_t bytes_read = read(proc_fd, buf, sizeof(buf) -1);
    close(proc_fd);
    if (bytes_read <= 0)
        return 0;
        
    buf[bytes_read] = '\0';

    /* Parse resident set size */
    unsigned long vm_size, rss;
    if (sscanf(buf, "%lu %lu", &vm_size, &rss) != 2)
        return 0;

    /* Convert from pages to bytes */
    return (uint64_t)(rss * sysconf(_SC_PAGESIZE));
#else
    return 0; /* Not on linux, so 0 */
#endif
}

/* thread specific tracking for linux */
static uint64_t get_thread_memory(jvmtiEnv *jvmti_env, JNIEnv *jni, jthread thread)
{
#ifdef __linux__
    /* get the native thread ID from the jthread */
    pid_t thread_id = get_native_thread_id(jvmti_env, jni, thread);
    if (thread_id == 0)
        return 0;

    /* Get thread-specific mem info */
    char proc_path[128];
    char buf[4096];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/statm", getpid(), thread_id);

    int fd = open(proc_path, O_RDONLY);
    if (fd < 0)
        return 0;

    ssize_t bytes_read = read(fd, buf, sizeof(buf) -1);
    close(fd);

    if (bytes_read <=0)
        return 0;

    buf[bytes_read] = '\0';

    /* parse values */
    unsigned long vm_size, rss;
    if (sscanf(buf, "%lu %lu", &vm_size, &rss) != 2)
        return 0;

    /* Convert from pages to bytes */
    return (uint64_t)(rss * sysconf(_SC_PAGESIZE));
#else
    return 0; /* Not on linux, so 0 */
#endif
}

/* Get current time in nanoseconds */
static uint64_t get_current_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t get_current_cpu_cycles() {
    /* In a real implementation, this would use CPU performance counters */
    return 0;
}

/**
 * Initialise a method_sample_t structure
 * 
 * Return NULL if it fails to allocate space in the provided arena
 */
static method_sample_t *init_method_sample(arena_t *arena, int method_index, jmethodID method_id)
{

    assert(arena != NULL);
    assert(method_id != NULL);
    assert(method_index >= 0);

    if (!arena || method_index < 0 || !method_id)
        return NULL;
    
    method_sample_t *sample = arena_alloc(arena, sizeof(method_sample_t));
    if (!sample)
        return NULL;

    /* Initialise sample */
    memset(sample, 0, sizeof(method_sample_t));
    sample->method_index = method_index;
    sample->method_id = method_id;
    sample->parent = NULL;
    
    unsigned int flags = global_ctx->metrics->metric_flags[method_index];

    if (flags & METRIC_FLAG_TIME)
        sample->start_time = get_current_time_ns();
    
    if (flags & METRIC_FLAG_MEMORY)
    {
        sample->start_process_memory = get_process_memory();
        sample->start_thread_memory = 0; /* TODO try and fix thread memory tracking later */
        sample->current_alloc_bytes = 0;
    }
        
    if (flags & METRIC_FLAG_CPU)
        sample->start_cpu = get_current_cpu_cycles();
    
    return sample;
}

/* Record method execution metrics */
void record_method_execution(agent_context_t *ctx, int method_index, 
    uint64_t exec_time_ns, uint64_t memory_bytes, uint64_t cycles) {

    method_metrics_soa_t *metrics = ctx->metrics;

    LOG_DEBUG("Recording metrics for index: %d, time=%lu, memory=%lu, cycles=%lu", 
        method_index, 
        (unsigned long)exec_time_ns, 
        (unsigned long)memory_bytes, 
        (unsigned long)cycles);

    /* Check for valid index */
    if (method_index < 0 || (size_t)method_index >= metrics->count) 
    {
        LOG_WARN("WARNING: method_index: %d not found in soa struct\n", method_index);
        return;
    }

    /* Lock metrics for thread safety */
    pthread_mutex_lock(&ctx->samples_lock);

    /* Update sample count */
    metrics->sample_counts[method_index]++;

    /* Update timing metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_TIME) != 0) {
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
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_MEMORY) != 0) {
        metrics->alloc_bytes[method_index] += memory_bytes;
        if (memory_bytes > metrics->peak_memory[method_index]) {
            metrics->peak_memory[method_index] = memory_bytes;
        }
    }

    /* Update CPU metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_CPU) != 0) {
        metrics->cpu_cycles[method_index] += cycles;
    }

    LOG_DEBUG("Method metrics updated: index=%d, samples=%lu, total_time=%lu, alloc=%lu", 
        method_index, 
        (unsigned long)metrics->sample_counts[method_index],
        (unsigned long)metrics->total_time_ns[method_index],
        (unsigned long)metrics->alloc_bytes[method_index]);
    
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

int start_thread(pthread_t *thread, thread_fn *fun, char *name, agent_context_t *ctx)
{
    int err = 0;
    err = pthread_create(thread, NULL, fun, ctx);
    if (err != 0)
    {
        printf("Failed to start %s thread: %d\n", name, err);
        return 1;
    }

    err = pthread_detach(*thread);
    if (err != 0)
    {
        printf("Failed to detach %s thread: %d\n", name, err);
        return 1;
    }
    return 0;
}

void export_to_file(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    if (!ctx->config.sample_file_path)
    {
        LOG_ERROR("No sample file path configured\n");
        return;
    }

    FILE *fp = fopen(ctx->config.sample_file_path, "w");
    if (!fp) 
    {
        LOG_ERROR("Failed to open sample file: %s\n", ctx->config.sample_file_path);
        return;
    }

    /* Lock metrics for thread safe exporting */
    pthread_mutex_lock(&ctx->samples_lock);
    /* Write header with time stamp */
    time_t now;
    time(&now);
    
    fprintf(fp, "# Method Metrics Export - %s", ctime(&now));
    fprintf(fp, "# Format: signature, call_count, sample_count, total_time_ns, avg_time_ns, min_time_ns, max_time_ns, alloc_bytes, peak_memory, cpu_cycles\n");

    /* Debug output to verify data being exported */
    LOG_DEBUG("Exporting %zu method metrics\n", ctx->metrics->count);

    /* Export the entire method_metrics_soa structure */
    size_t total_calls = 0;
    size_t total_samples = 0;
    for (size_t i = 0; i < ctx->metrics->count; i++)
    {
        if (ctx->metrics->signatures[i])
        {
            /* Calculate avg time if samples exist */
            uint64_t avg_time = 0;
            if (ctx->metrics->sample_counts[i] > 0)
                avg_time = ctx->metrics->total_time_ns[i] / ctx->metrics->sample_counts[i];

            total_calls += ctx->metrics->call_counts[i];
            total_samples += ctx->metrics->sample_counts[i];

            /* Debug output to verify each method's metrics */
            LOG_DEBUG("Method[%zu]: %s, calls=%lu, samples=%lu, time=%lu\n", 
                i, 
                ctx->metrics->signatures[i],
                (unsigned long)ctx->metrics->call_counts[i],
                (unsigned long)ctx->metrics->sample_counts[i],
                (unsigned long)ctx->metrics->total_time_ns[i]);

            /* Print out the details */
            fprintf(fp, "%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
                ctx->metrics->signatures[i],
                (unsigned long)ctx->metrics->call_counts[i],
                (unsigned long)ctx->metrics->sample_counts[i],
                (unsigned long)ctx->metrics->total_time_ns[i],
                (unsigned long)avg_time,
                (unsigned long)(ctx->metrics->min_time_ns[i] == UINT64_MAX ? 0 : ctx->metrics->min_time_ns[i]),
                (unsigned long)ctx->metrics->max_time_ns[i],
                (unsigned long)ctx->metrics->alloc_bytes[i],
                (unsigned long)ctx->metrics->peak_memory[i],
                (unsigned long)ctx->metrics->cpu_cycles[i]);
        }
    }

    /* Add summary statistics */
    fprintf(fp, "\n# Summary Statistics\n");
    fprintf(fp, "Total methods tracked: %zu\n", ctx->metrics->count);
    fprintf(fp, "Total method calls: %lu\n", (unsigned long)total_calls);
    fprintf(fp, "Total samples collected: %lu\n", (unsigned long)total_samples);

    LOG_DEBUG("Export complete: methods=%zu, calls=%lu, samples=%lu\n", 
        ctx->metrics->count, (unsigned long)total_calls, (unsigned long)total_samples);

    pthread_mutex_unlock(&ctx->samples_lock);

    fclose(fp);
}

void *export_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;

    LOG_INFO("Export thread started, interval=%d seconds\n", ctx->config.export_interval);
    
    /* Initial export to create the file */
    export_to_file(ctx);

    /* export to file while export_running flag is set */
    while (ctx->export_running) 
    {
        LOG_DEBUG("Export thread sleeping for %d seconds\n", ctx->config.export_interval);
        /* Sleep in smaller increments to be more responsive to shutdown */
        for (int i = 0; i < ctx->config.export_interval && ctx->export_running; i++) {
            sleep(1);
        }
        if (ctx->export_running) {
            LOG_DEBUG("Export thread woke up, exporting metrics\n");
            export_to_file(ctx);
        }
    }

    /* Final write on shutdown */
    LOG_INFO("Export thread shutting down, performing final export\n");
    export_to_file(ctx);
    
    LOG_INFO("Export thread terminated\n");
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

    /* Get thread-local context */
    thread_context_t *context = get_thread_local_context();

    if (!context)
        return;

    if (jvmti != global_ctx->jvmti_env)
        LOG_WARN("WARNING: jvmti (%p) differs from global_ctx->jvmti_env (%p)\n", jvmti, global_ctx->jvmti_env);

    err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetClassSignature(jvmti, declaring_class, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    if (strstr(class_signature, "com/github"))
        LOG_DEBUG("Should we sample...: class_sig: (%s) method_name: (%s) method_sig (%s) \n", class_signature, method_name, method_signature);

    /* Check if we should sample this method call */
    int sample_index = should_sample_method(global_ctx, class_signature, method_name, method_signature);

    if (sample_index > 0) {
        /* We're sampling this call */
        LOG_DEBUG("Sampling : %s (%d)\n", method_name, sample_index);

        /* Create a new sample on our method stack */
        arena_t *arena = find_arena(global_ctx->arena_head, "sample_arena");
        if (!arena)
        {
            LOG_ERROR("Could not find sample_arena!\n");
            goto deallocate;
        }

        /* Now create the actual sample with the correct data */
        method_sample_t *sample = init_method_sample(arena, sample_index -1, method); /* Convert sample_index back to 0-based index */
        if (!sample)
        {
            LOG_ERROR("Failed to allocate method sample context!\n");
            goto deallocate;
        }

        /* Now we update our sample stack */
        /* 1. This sample's parent is whatever is in the current context... */
        sample->parent = context->sample;
        /* 2. Overwrite the context's sample with this sample */
        context->sample = sample;
        /* 3. Increase our stack depth */
        context->stack_depth++;
        
        LOG_INFO("[ENTRY] Sampling method %s.%s%s with jmethodID [%p]\n", 
            class_signature, method_name, method_signature, method);
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
    /* Get thread-local context */
    thread_context_t *context = get_thread_local_context();

    if (!context || !context->sample || context->sample->method_index < 0)
        return;
    

    /* We need to look in our stack to find a corresponding method entry 
    Note that the JVM doesn't guarantee ordering of method entry/exits for a variety of reasons:
    - Threading
    - Optimizations
    - etc
    */
    method_sample_t *current = context->sample;
    method_sample_t *parent = NULL;
    method_sample_t *target = NULL;

    /* Top of stack matches - quick case */
    if (current != NULL && current->method_id == method)
    {
        target = current;
        context->sample = current->parent; /* Pop from top of stack */
        context->stack_depth--;
    }
    else if (current != NULL)
    {
        /* We need to search the stack for a matching method - this seems to be the common case */
        LOG_DEBUG("Method exit mismatch, searching for method [%p] in stack\n");

        /* Traverse stack to find target */
        while(current)
        {
            if (current->method_id == method)
            {
                target = current;
                /* Remove node from linked-list/stack */
                if (parent)
                    parent->parent = current->parent; /* Skip over this node */
                else
                    context->sample = current->parent; /* Update head of list */

                context->stack_depth--;
                break;
            }
            /* not found, move onto next */
            parent = current;
            current = current->parent;
        }
    }

    /* Only process the exit if it matches the current method at the top of our stack of samples */
    if (!target)
    {
        LOG_DEBUG("No matching method found for methodID [%p]\n", method);
        return;
    }


    LOG_DEBUG("Matching method found for methodID [%p]\n", method);
    unsigned int flags = 0; 
    
    if (target->method_index >= 0 && (size_t)target->method_index < global_ctx->metrics->count)
        flags = global_ctx->metrics->metric_flags[target->method_index];
    
    /* Get metrics if they were enabled */
    uint64_t exec_time = 0;
    uint64_t memory_delta = 0;
    uint64_t cpu_delta = 0;
    
    /* Calculate execution time */
    if ((flags & METRIC_FLAG_TIME) != 0 && target->start_time > 0)
    {
        uint64_t end_time = get_current_time_ns();
        exec_time = end_time - target->start_time;
    }

    if ((flags & METRIC_FLAG_MEMORY) != 0) {
        LOG_DEBUG("sampling memory for %d\n", target->method_index);
        /* Select the most specific memory metric available:
         * 1. Direct object allocations (most specific)
         * 2. Thread memory change
         * 3. Process memory change
         */

         /* JVM heap allocations during method execution */
        memory_delta = target->current_alloc_bytes;

        /* If no direct allocations check OS-level thread mem changes */
        if (memory_delta == 0 && target->start_thread_memory > 0)
        {
            uint64_t end_thread_memory = get_thread_memory(jvmti, jni, thread);
            if (end_thread_memory > target->start_thread_memory)
                memory_delta = end_thread_memory - target->start_thread_memory;
        }

        /* If there's still no change, look for process wide memory changes */
        if (memory_delta == 0 && target->start_thread_memory > 0)
        {
            uint64_t end_process_memory = get_process_memory();
            if (end_process_memory > target->start_process_memory)
                memory_delta = end_process_memory - target->start_process_memory;
        }
    }
    
    if ((flags & METRIC_FLAG_CPU) != 0) {
        uint64_t end_cpu = get_current_cpu_cycles();

        if (end_cpu > target->start_cpu)
            cpu_delta = end_cpu - target->start_cpu;
        else
            LOG_DEBUG("Invalid CPU cycles: end=%llu, start=%llu", (unsigned long long)end_cpu, (unsigned long long)target->start_cpu);
    }
    
    /* Record the metrics */
    record_method_execution(global_ctx, target->method_index, exec_time, memory_delta, cpu_delta);

    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaringClass;
    jvmtiError err;

    /* Get method details for logging */
    if (tls_initialized && flags != 0) {
        /* Get method name */
        err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG_ERROR("GetMethodName failed with error %d\n", err);
            return; /* Cannot do anything in this case */
        }

        /* Get declaring class */
        err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaringClass);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG_ERROR("GetMethodDeclaringClass failed with error %d\n", err);
            goto deallocate;
        }

        /* Get class signature */
        err = (*jvmti)->GetClassSignature(jvmti, declaringClass, &class_signature, NULL);
        if (err != JVMTI_ERROR_NONE)
        {
            LOG_ERROR(" GetClassSignature failed with error %d\n", err);
            goto deallocate;
        }
        
        LOG_INFO("[EXIT] Method %s.%s%s executed in %llu ns, memory delta: %llu bytes\n", 
            class_signature, method_name, method_signature, 
            (unsigned long long)exec_time, (unsigned long long)memory_delta);
    }

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
        LOG_ERROR("GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    jclass method_class;
    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &method_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }
    
    /* Get class name */
    err = (*jvmti_env)->GetClassSignature(jvmti_env, method_class, &class_name, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }
        
    /* Convert Java exception to string representation */
    jclass exception_class = (*jni_env)->GetObjectClass(jni_env, exception);
    jmethodID toString_id = (*jni_env)->GetMethodID(jni_env, exception_class, "toString", "()Ljava/lang/String;");
    jstring exception_str = (*jni_env)->CallObjectMethod(jni_env, exception, toString_id);
    if ((*jni_env)->ExceptionCheck(jni_env)) 
    {
        LOG_ERROR("JNI exception occurred while getting exception string\n");
        (*jni_env)->ExceptionClear(jni_env);
        goto deallocate;
    }
    
    /* Convert to standard C string */
    const char *exception_cstr = exception_str ? (*jni_env)->GetStringUTFChars(jni_env, exception_str, NULL) : "Unknown exception";
    
    LOG_DEBUG("Exception in %s.%s%s at location %ld\n", class_name, method_name, method_signature, (long)location);
    LOG_DEBUG("Exception details: %s\n", exception_cstr);
    
    /* Get the local variable table for this method */
    jint entry_count = 0;
    err = (*jvmti_env)->GetLocalVariableTable(jvmti_env, method, &entry_count, &table);

    /* all other errors just bail */
    if (err != JVMTI_ERROR_NONE && err != JVMTI_ERROR_ABSENT_INFORMATION)
    {
        LOG_WARN("Could not get local variable table %d\n", err);
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

        LOG_DEBUG("Method params: \n");

        arena_t *arena = find_arena(global_ctx->arena_head, "exception_arena");
        if (arena == NULL)
        {
            LOG_ERROR(">> Unable to find exception arena on list! <<\n");
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

            LOG_DEBUG("\tParam %d (%s): %s\n", 
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
            LOG_ERROR("GetMethodName for catch_method failed with error %d\n", err);
            goto deallocate;
        }
        
        LOG_DEBUG("Caught in method: %s%s at location %ld\n", catch_method_name, catch_method_signature, (long)catch_location);
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

static void JNICALL object_alloc_callback(jvmtiEnv *jvmti_env, JNIEnv *jni, jthread thread, jobject object, jclass klass, jlong size)
{
    /* Get thread-local context to prevent re-entrancy */
    thread_context_t *context = get_thread_local_context();
    if (!context || !context->sample)
        return;
    
    // char* class_sig;
    // (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);
    // LOG(global_ctx, "DEBUG Allocated object of class: %s, size: %lld\n", class_sig, size);
    // (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_sig);
    
    method_sample_t *sample = context->sample;
    if (!sample) return;

    /* Check if memory metrics are enabled for this method */
    if (sample->method_index < 0 || 
        (size_t)sample->method_index >= global_ctx->metrics->count || 
        !(global_ctx->metrics->metric_flags[sample->method_index] & METRIC_FLAG_MEMORY))
        return;

    
    /* Add allocation to the current method being sampled */
    sample->current_alloc_bytes += size;

    LOG_DEBUG("Allocation: %lld bytes for method_index %d, total: %lld", 
         (long long)size, sample->method_index, (long long)sample->current_alloc_bytes);
    
    /* Optionally, get class name for detailed logging */
    if (current_log_level <= LOG_LEVEL_DEBUG) {
        if ((global_ctx->metrics->metric_flags[sample->method_index] & METRIC_FLAG_MEMORY) != 0) {
            char* class_sig;
            jvmtiError err = (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);
            if (err == JVMTI_ERROR_NONE) {
                LOG_DEBUG("Allocated object of class: %s, size: %lld\n", 
                    class_sig, (long long)size);
                (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_sig);
            }
        }
    }
}

static void JNICALL thread_end_callback(jvmtiEnv *jvmit, JNIEnv *jni, jthread thread)
{
    thread_context_t *context = pthread_getspecific(context_key);
    if (context) 
    {
        /* No need to manually free each call since they're arena-allocated */
        context->sample = NULL;
        context->stack_depth = 0;
        
        /* Free the context itself */
        free(context);
        pthread_setspecific(context_key, NULL);
    }

    if (!thread)
        return;

    /* Get the thread Id */
    jclass thread_class = (*jni)->GetObjectClass(jni, thread);
    jmethodID get_id_method = (*jni)->GetMethodID(jni, thread_class, "getId", "()J");

    if (get_id_method)
    {
        jlong thread_id = (*jni)->CallLongMethod(jni, thread, get_id_method);

        /* remove from our mapping table */
        pthread_mutex_lock(&global_ctx->samples_lock);
        for (int i = 0; i < MAX_THREAD_MAPPINGS; i++) 
        {
            if (global_ctx->thread_mappings[i].java_thread_id == thread_id) 
            {
                global_ctx->thread_mappings[i].java_thread_id = 0;
                global_ctx->thread_mappings[i].native_thread_id = 0;
                break;
            }
        }
        pthread_mutex_unlock(&global_ctx->samples_lock);
    }
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
    
    LOG_INFO("INFO: loading config from: %s, default config_file: %s\n", cf, DEFAULT_CFG_FILE);
    if (!cf) 
        cf = DEFAULT_CFG_FILE;
    
    FILE *fp = fopen(cf, "r");
    if (!fp) 
    {
        LOG_ERROR("Could not open config file: %s\n", cf);
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
            LOG_DEBUG("Processing line in [method_signatures]: '%s'\n", processed);
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
                LOG_ERROR("Invalid method filter format: %s\n", processed);
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
                LOG_ERROR("Failed to add method filter: %s\n", full_sig);
                continue;
            }
            
            LOG_DEBUG("Added method filter #%d: '%s' with rate=%d\n", 
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
                        LOG_WARN("WARNING: Invalid interval value: %s\n", value);
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
            LOG_ERROR("Failed to set default export_method\n");
    }
    
    LOG_INFO("Config loaded: default_rate=%d, filters=%d, path=%s, method=%s\n",
        ctx->config.rate, ctx->config.num_filters,
        ctx->config.sample_file_path ? ctx->config.sample_file_path : "NULL",
        ctx->config.export_method ? ctx->config.export_method : "NULL");
    
    return res;
}

/**
 * Helper function to initialize the metrics Struct-of-Arrays structure
 */
method_metrics_soa_t *init_method_metrics(arena_t *arena, size_t initial_capacity) 
{
    assert(arena != NULL);

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
    for (size_t i = 0; i < initial_capacity; i++)
        metrics->min_time_ns[i] = UINT64_MAX;
    
    return metrics;
}

/**
 * Add a method to the metrics structure
 */
int add_method_to_metrics(agent_context_t *ctx, const char *signature, int sample_rate, unsigned int flags) 
{
    
    assert(ctx != NULL);
    assert(ctx->metrics != NULL);

    method_metrics_soa_t *metrics = ctx->metrics;

    /* Add debug output to see what's being added */
    LOG_DEBUG("Adding method to metrics: %s (rate=%d, flags=%u)\n", 
        signature, sample_rate, flags);

    /* Check if method already exists */
    int index = find_method_index(metrics, signature);
    if (index >= 0) 
    {
        /* Update existing entry */
        metrics->sample_rates[index] = sample_rate;
        metrics->metric_flags[index] = flags;
        LOG_DEBUG("Updated existing method at index %d\n", index);
        return index;
    }
    
    /* Need to add a new entry */
    if (metrics->count >= metrics->capacity) 
    {
        /* Cannot grow in the current implementation with arenas */
        LOG_DEBUG("Method metrics capacity reached (%zu)\n", metrics->capacity);
        return -1;
    }
    
    /* Add new entry */
    arena_t *arena = find_arena(ctx->arena_head, "metrics_arena");
    if (!arena) 
    {
        LOG_DEBUG("Could not find metrics arena\n");
        return -1;
    }
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
    LOG_DEBUG("Added new method at index %d, total methods: %zu\n", 
        index, metrics->count);
    return index;
}

/**
 * Find the index of a method in the metrics structure
 */
int find_method_index(method_metrics_soa_t *metrics, const char *signature) 
{
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
                         const char *method_name, const char *method_signature) 
{
    /* We need to find the method in our metrics structure */
    char full_sig[MAX_SIG_SZ];
    int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", 
                        class_signature, method_name, method_signature);
    
    /* Signature is too long, skip */
    if (written < 0 || written >= MAX_SIG_SZ)
        return 0;
    
    int method_index = find_method_index(ctx->metrics, full_sig);
    
    /* If exact match not found, try class wildcard */
    if (method_index < 0) {
        written = snprintf(full_sig, sizeof(full_sig), "%s * *", class_signature);
        if (written >= 0 && written < MAX_SIG_SZ) {
            method_index = find_method_index(ctx->metrics, full_sig);
        }
    }
    
    /* If still not found, not a method we want to sample */
    if (method_index < 0)
        return 0;
    
    /* Lock to safely update call count */
    pthread_mutex_lock(&ctx->samples_lock);

    /* We found the method, increment its call count */
    ctx->metrics->call_counts[method_index]++;
    uint64_t current_count = ctx->metrics->call_counts[method_index];

    /* Log call count updates for debugging */
    LOG_DEBUG("Method %s call_count incremented to %lu\n", 
        ctx->metrics->signatures[method_index], 
        (unsigned long)current_count);

    /* Check if we should sample this call based on the sample rate */
    int should_sample = ctx->metrics->call_counts[method_index] % ctx->metrics->sample_rates[method_index];

    pthread_mutex_unlock(&ctx->samples_lock);

    if (should_sample)
        return method_index + 1;  /* +1 because 0 means "don't sample" */
    
    return 0;  /* Don't sample this call */
}

static int init_jvm_capabilities(agent_context_t *ctx)
{
    assert(ctx != NULL);

    if (!ctx) return 1;

    jvmtiCapabilities capabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError err;

    /* Enable capabilities */
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_method_entry_events = 1;
    capabilities.can_generate_method_exit_events = 1;
    capabilities.can_generate_exception_events = 1;
    capabilities.can_access_local_variables = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;
    capabilities.can_generate_vm_object_alloc_events = 1;
    capabilities.can_tag_objects = 1;

    err = (*global_ctx->jvmti_env)->AddCapabilities(global_ctx->jvmti_env, &capabilities);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("AddCapabilities failed with error %d\n", err);
        return 1;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;
    callbacks.Exception = &exception_callback;
    callbacks.VMObjectAlloc = &object_alloc_callback;
    callbacks.ThreadEnd = &thread_end_callback;

    err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("SetEventCallbacks failed with error %d\n", err);
        return 1;
    }

    /* Enable event notifications */
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return 1;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return 1;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return 1;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return 1;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_VM_OBJECT_ALLOC, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("Could not enable allocation events: %d\n", err);
        return 1;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_THREAD_END, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Could not enable thread end events: %d\n", err);
        return 1;
    }

    return 0; /* Success */
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    /* Allocate and initialize the agent context */
    global_ctx = malloc(sizeof(agent_context_t));
    if (!global_ctx) 
    {
        printf("Failed to allocate agent context\n");
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
    memset(global_ctx->thread_mappings, 0, sizeof(global_ctx->thread_mappings));

    /* Redirect output */
    if (options && strncmp(options, "logfile=", 8) == 0)
    {
        global_ctx->log_file = fopen(options + 8, "w");
        if (!global_ctx->log_file)
        {
            printf("Failed to open log file: %s, reverting to stdout\n", options + 8);
            global_ctx->log_file = stdout;
        }
    }

    /* Enable debug output */
    if (options && strncmp(options, "debug", 5) == 0)
        current_log_level = LOG_LEVEL_DEBUG;

    log_q_t *log_queue = malloc(sizeof(log_q_t));

    /* 
      We initialise all the arenas we need in this function and we
      destroy all the arenas in the corresponding Agent_OnUnload
    */

    /* Number of arena configurations in the table */
    const size_t num_arenas = sizeof(arena_configs) / sizeof(arena_configs[0]);
    /* Create each arena from the configuration table */
    for (size_t i = 0; i < num_arenas; i++) {
        arena_t *arena = create_arena(
            &global_ctx->arena_head, 
            &global_ctx->arena_tail, 
            arena_configs[i].name, 
            arena_configs[i].size, 
            arena_configs[i].block_count
        );
        
        if (!arena) 
        {
            printf("Failed to create %s\n", arena_configs[i].name);
            return JNI_ERR;
        }
    }

    /* Init logging after all arenas are created */
    arena_t *log_arena = find_arena(global_ctx->arena_head, "log_arena");
    if (!log_arena) 
    {
        printf("Log arena not found\n");
        return JNI_ERR;
    }

    /* We start the logging thread as we initialise the system now */
    if (init_log_system(log_queue, global_ctx->arena_head, global_ctx->log_file) != 0)
    {
        cleanup(global_ctx);
        return JNI_ERR;
    }

    /* Initialize metrics after all arenas are created */
    arena_t *metrics_arena = find_arena(global_ctx->arena_head, "metrics_arena");
    if (!metrics_arena) 
    {
        LOG_ERROR("Metrics arena not found\n");
        return JNI_ERR;
    }

    size_t initial_capacity = 256;
    global_ctx->metrics = init_method_metrics(metrics_arena, initial_capacity);
    if (!global_ctx->metrics) {
        LOG_ERROR("Failed to initialize metrics structure\n");
        return JNI_ERR;
    }

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || global_ctx->jvmti_env == NULL) 
    {
        LOG_ERROR("Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    /* Now we have logging configured, load config */
    if (load_config(global_ctx, "./trace.ini") != 0)
    {
        LOG_ERROR("Unable to load config_file!\n");
        return JNI_ERR;
    }

    LOG_INFO("Config: rate=%d, method='%s', path='%s'\n",
        global_ctx->config.rate, global_ctx->config.export_method, global_ctx->config.sample_file_path);

    if (strcmp(global_ctx->config.export_method, "file") != 0)
    {
        LOG_ERROR("Unknown export method: [%s]", global_ctx->config.export_method);
        return JNI_ERR;
    }

    /* Set export_running to true before starting the thread */
    global_ctx->export_running = 1;

    /* Init the event/sample handling */
    if (start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != 0)
    {
        cleanup(global_ctx);
        cleanup_log_system();
        return JNI_ERR;
    }

    if (init_jvm_capabilities(global_ctx) != 0)
        return JNI_ERR;

    LOG_INFO("JVMTI Agent Loaded.\n");
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
        pthread_mutex_lock(&global_ctx->samples_lock);
        global_ctx->export_running = 0;
        pthread_mutex_unlock(&global_ctx->samples_lock);
        
        /* Give the export thread a moment to perform final export */
        usleep(100000); /* 100ms should be enough for final export */

        pthread_t export_thread_copy = global_ctx->export_thread;
        pthread_detach(global_ctx->export_thread);
        LOG_INFO("Waiting for export thread to terminate\n");
        safe_thread_join(export_thread_copy, 2);

        cleanup(global_ctx);
        /* Clean up thread-local storage */
        if (tls_initialized) 
        {
            /* Free the current thread's TLS data */
            thread_context_t *context = pthread_getspecific(context_key);
            if (context) {
                free(context);
                pthread_setspecific(context_key, NULL);
            }
            
            /* Unfortunately, with pthreads there's no direct way to iterate and free 
               thread-local storage from all threads. It relies on thread exit handlers.
               We can at least delete the key to prevent further allocations. */
            /* Clean up TLS resources */
            pthread_key_delete(context_key);
            tls_initialized = 0;
            
            /* Destroy the initialization mutex */
            pthread_mutex_destroy(&tls_init_mutex);
            
            /* Note: Any other thread that was using TLS will have its destructor called
               when that thread exits. If the JVM creates a lot of threads that don't exit,
               there could still be leaks. This is a limitation of the pthreads API. */
            LOG_WARN("Thread-local storage cleanup may be incomplete for threads that don't exit\n");
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