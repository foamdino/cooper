/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"

static agent_context_t *global_ctx = NULL; /* Single global context */

/* Thread-local storage key and initialization mutex */
static pthread_key_t context_key;
static pthread_once_t tls_init_once = PTHREAD_ONCE_INIT;

/* Arena configurations */
static const arena_config_t arena_configs[] = {
    {EXCEPTION_ARENA_ID, EXCEPTION_ARENA_NAME, EXCEPTION_ARENA_SZ, EXCEPTION_ARENA_BLOCKS},
    {LOG_ARENA_ID, LOG_ARENA_NAME, LOG_ARENA_SZ, LOG_ARENA_BLOCKS},
    {SAMPLE_ARENA_ID, SAMPLE_ARENA_NAME, SAMPLE_ARENA_SZ, SAMPLE_ARENA_BLOCKS},
    {CONFIG_ARENA_ID, CONFIG_ARENA_NAME, CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS},
    {METRICS_ARENA_ID, METRICS_ARENA_NAME, METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS},
    {SCRATCH_ARENA_ID, SCRATCH_ARENA_NAME, SCRATCH_ARENA_SZ, SCRATCH_ARENA_BLOCKS},
    {CLASS_CACHE_ARENA_ID, CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS}
};

#ifdef ENABLE_DEBUG_LOGS
/* Debug function for dumping method stack */
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
#endif

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

static void init_thread_local_storage_once(void)
{
    pthread_key_create(&context_key, destroy_thread_context);
}

/* Initialize thread-local storage */
static void init_thread_local_storage() 
{
    pthread_once(&tls_init_once, init_thread_local_storage_once);
}

/* Get the thread-local sample structure */
static thread_context_t *get_thread_local_context() 
{
    init_thread_local_storage();
    
    thread_context_t *context = pthread_getspecific(context_key);
    if (!context) 
    {
        /* First time this thread is accessing the key */
        context = calloc(1, sizeof(thread_context_t));
        if (context) 
        {
            context->sample = NULL;
            context->stack_depth = 0;
            pthread_setspecific(context_key, context);
        }
    }
    
    return context;
}

/** 
 * Get cached class signature or fetch if not cached 
 * @return COOPER_OK on success, COOPER_ERR on failure
 * output_buffer contains class signature
 */
static int get_cached_class_signature(jvmtiEnv *jvmti_env, jclass klass, char **output_buffer)
{   
    if (!output_buffer || !jvmti_env || !klass)
        return COOPER_ERR;
    
    jlong tag = 0;
    jvmtiError err = (*jvmti_env)->GetTag(jvmti_env, klass, &tag);
    if (err != JVMTI_ERROR_NONE)
        return COOPER_ERR;

    /* If we don't have a tag, there's nothing we can do here */
    if (tag == 0)
        return COOPER_ERR;

    class_info_t *info = (class_info_t*)(intptr_t)tag;
    *output_buffer = info->class_sig;
    return COOPER_OK;
}

/**
 * Get a native thread id for a given java vm thread 
 * 
 * NOTE this is linux specific and will always return 0 on other platforms
 * 
 * @param jvmti_env Pointer to the JVMTI env
 * @param jni Pointer to the JNI env
 * @param thread a jthread
 * 
 * @return a pid_t (or 0 if not found)
 */
static pid_t get_native_thread_id(jvmtiEnv *jvmti_env, JNIEnv *jni, jthread thread)
{
#ifdef __linux__
    pid_t result = 0;

    jvmtiPhase jvm_phase;
    if ((*jvmti_env)->GetPhase(jvmti_env, &jvm_phase) != JVMTI_ERROR_NONE || jvm_phase != JVMTI_PHASE_LIVE)
    {
        LOG_DEBUG("Cannot get the thread id as jvm is not in correct phase: %d", jvm_phase);
        return 0;
    }

    if (global_ctx->java_thread_class == NULL || global_ctx->getId_method == NULL)
    {
        LOG_ERROR("Failed to get Thread class or getId method");
        return 0;
    }

    /* Get the jvm thread id */
    jlong thread_id = (*jni)->CallLongMethod(jni, thread, global_ctx->getId_method);
    if ((*jni)->ExceptionCheck(jni)) 
    {
        (*jni)->ExceptionClear(jni);
        LOG_ERROR("Exception occurred while getting thread ID");
        return 0;
    }

    LOG_DEBUG("Looking up Java thread ID: %lld", (long long)thread_id);

    /* Use Thread.getId() as a key to our mapping table */
    pthread_mutex_lock(&global_ctx->samples_lock);

    /* Check for previous mapping */
    for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
    {
        if (global_ctx->thread_mappings[i].java_thread_id == thread_id)
        {
            result = global_ctx->thread_mappings[i].native_thread_id;
            LOG_DEBUG("Found existing mapping: Java ID %lld -> Native ID %d", (long long)thread_id, result);
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
        jvmtiError err = (*jvmti_env)->GetCurrentThread(jvmti_env, &current_thread);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG_ERROR("GetCurrentThread failed with error %d", err);
            return 0;
        }

        jboolean is_same_thread = (*jni)->IsSameObject(jni, thread, current_thread);
        (*jni)->DeleteLocalRef(jni, current_thread);
        if (is_same_thread)
        {
            result = syscall(SYS_gettid);
            LOG_DEBUG("Current thread ID: %d for Java thread ID: %lld", result, (long long)thread_id);

            /* Add to our map */
            int empty_slot = -1;
            pthread_mutex_lock(&global_ctx->samples_lock);
            for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
            {
                if (global_ctx->thread_mappings[i].java_thread_id == 0)
                {
                    empty_slot = i;
                    break;
                }
            }

            if (empty_slot >= 0)
            {
                global_ctx->thread_mappings[empty_slot].java_thread_id = thread_id;
                global_ctx->thread_mappings[empty_slot].native_thread_id = result;
            } 
            else
                LOG_ERROR("No empty slots available for thread mapping");

            pthread_mutex_unlock(&global_ctx->samples_lock);
        }
        else
            LOG_DEBUG("Cannot get native ID for non-current thread");
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
    int proc_fd = -1;
    char buf[4096];

    /* Open procfs file */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/statm", getpid());
    proc_fd = open(proc_path, O_RDONLY);

    if (proc_fd < 0)
        return 0;

    ssize_t bytes_read = read(proc_fd, buf, sizeof(buf) -1);
    close(proc_fd);
    if (bytes_read <= 0)
        return 0;
        
    buf[bytes_read] = '\0';

    /* Parse resident set size */
    unsigned long vm_size, rss;
    int res = sscanf(buf, "%lu %lu", &vm_size, &rss);

    if (res != 2)
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
    {
        LOG_DEBUG("Could not get native thread ID for thread");
        return 0;
    }
    
    /* Get thread-specific mem info */
    char proc_path[128];
    char buf[4096];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/statm", getpid(), thread_id);
    LOG_DEBUG("Reading thread memory from %s", proc_path);

    int fd = open(proc_path, O_RDONLY);
    if (fd < 0)
    {
        LOG_DEBUG("Could not open %s: %s", proc_path, strerror(errno));
        return 0;
    }

    ssize_t bytes_read = read(fd, buf, sizeof(buf) -1);
    close(fd);

    if (bytes_read <=0)
    {
        LOG_DEBUG("Failed to read from %s: %s", proc_path, strerror(errno));
        return 0;
    }

    buf[bytes_read] = '\0';

    /* parse values */
    unsigned long vm_size, rss;
    if (sscanf(buf, "%lu %lu", &vm_size, &rss) != 2)
    {
        LOG_DEBUG("Failed to parse memory values from %s", buf);
        return 0;
    }

    /* Convert from pages to bytes */
    uint64_t memory_bytes = (uint64_t)(rss * sysconf(_SC_PAGESIZE));
    LOG_DEBUG("Thread %d memory: %llu bytes", thread_id, (unsigned long long)memory_bytes);
    return memory_bytes;
#else
    return 0; /* Not on linux, so 0 */
#endif
}

/* Get current time in nanoseconds */
static uint64_t get_current_time_ns() 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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
    sample->method_index = method_index;
    sample->method_id = method_id;
    /* current_alloc_bytes and parent already zero-initialized by arena_alloc */
    
    unsigned int flags = global_ctx->metrics->metric_flags[method_index];

    if (flags & METRIC_FLAG_TIME)
        sample->start_time = get_current_time_ns();
        
    if (flags & METRIC_FLAG_CPU)
        sample->start_cpu = cycles_start();
    
    return sample;
}

/* Record method execution metrics */
void record_method_execution(agent_context_t *ctx, int method_index, uint64_t exec_time_ns, uint64_t memory_bytes, uint64_t cycles) 
{
    method_metrics_soa_t *metrics = ctx->metrics;

    LOG_DEBUG("Recording metrics for index: %d, time=%lu, memory=%lu, cycles=%lu\n", 
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

    /* Update sample count */
    __atomic_add_fetch(&metrics->sample_counts[method_index], 1, __ATOMIC_RELAXED);

    /* Update timing metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_TIME) != 0) 
    {
        __atomic_add_fetch(&metrics->total_time_ns[method_index], exec_time_ns, __ATOMIC_RELAXED);

        /* Update min/max */
        pthread_mutex_lock(&ctx->samples_lock);

        if (exec_time_ns < metrics->min_time_ns[method_index]) 
            metrics->min_time_ns[method_index] = exec_time_ns;

        if (exec_time_ns > metrics->max_time_ns[method_index]) 
            metrics->max_time_ns[method_index] = exec_time_ns;
        
        pthread_mutex_unlock(&ctx->samples_lock);
    }

    /* Update memory metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_MEMORY) != 0) 
    {
        __atomic_add_fetch(&metrics->alloc_bytes[method_index], memory_bytes, __ATOMIC_RELAXED);

        pthread_mutex_lock(&ctx->samples_lock);

        if (memory_bytes > metrics->peak_memory[method_index])
            metrics->peak_memory[method_index] = memory_bytes;
            
        pthread_mutex_unlock(&ctx->samples_lock);
    }

    /* Update CPU metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_CPU) != 0)
        __atomic_add_fetch(&metrics->cpu_cycles[method_index], cycles, __ATOMIC_RELAXED);

    LOG_DEBUG("Method metrics updated: index=%d, samples=%lu, total_time=%lu, alloc=%lu", 
        method_index, 
        (unsigned long)metrics->sample_counts[method_index],
        (unsigned long)metrics->total_time_ns[method_index],
        (unsigned long)metrics->alloc_bytes[method_index]);
}

static object_allocation_metrics_t *init_object_allocation_metrics(arena_t *arena, size_t initial_capacity)
{

    assert(arena != NULL);

    object_allocation_metrics_t *metrics = arena_alloc_aligned(arena, sizeof(object_allocation_metrics_t), CACHE_LINE_SZ);
    if (!metrics)
        return NULL;

    metrics->capacity = initial_capacity;

    /* Allocate arrays in SoA structure */
    metrics->class_signatures = arena_alloc_aligned(arena, initial_capacity * sizeof(char*), CACHE_LINE_SZ);
    metrics->allocation_counts = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->total_bytes = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->peak_instances = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->current_instances = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->min_size = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->max_size = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->avg_size = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);

    if (!metrics->class_signatures || !metrics->allocation_counts || !metrics->total_bytes ||
        !metrics->peak_instances || !metrics->current_instances || !metrics->min_size || 
        !metrics->max_size || !metrics->avg_size)
        return NULL;
    
    /* Set min_size to maximum value initially */
    for (size_t i = 0; i < initial_capacity; i++)
        metrics->min_size[i] = UINT64_MAX;
    
    return metrics;
}

/**
 * 
 * @return position in array of object allocation stats or -1 if no space left
 */
static int find_or_add_object_type(object_allocation_metrics_t *obj_metrics, const char *class_sig)
{
    assert(obj_metrics != NULL);
    assert(class_sig != NULL);

    if (!obj_metrics)
    {
        LOG_ERROR("ob_metrics is NULL!\n");
        return -1;
    }

    if (!class_sig)
    {
        LOG_ERROR("class_sig is NULL!\n");
        return -1;
    }
    
    for (size_t i = 0; i < obj_metrics->count; i++)
    {
        if (obj_metrics->class_signatures[i] != NULL)
        {
            if (strcmp(obj_metrics->class_signatures[i], class_sig) == 0)
                return i;
        }
        else
        {
            LOG_ERROR("class_signatures[%d] is NULL when count=%zu\n", i, obj_metrics->count);
            return -1;
        }
    }

    /* Do we have space to add new allocation stats? */
    if (obj_metrics->count >= obj_metrics->capacity)
    {
        LOG_WARN("Object metrics capacity reached (%zu)\n", obj_metrics->capacity);
        return -1;
    }

    arena_t *arena = global_ctx->arenas[METRICS_ARENA_ID];
    if (!arena)
    {
        LOG_ERROR("unable to find metrics arena!\n");
        return -1;
    }

    int index = obj_metrics->count;

    obj_metrics->class_signatures[index] = arena_strdup(arena, class_sig);
    if (!obj_metrics->class_signatures[index]) 
    {
        LOG_ERROR("Failed to allocate memory for class signature: %s\n", class_sig);
        return -1;
    }

    /* Only set non-zero values, the rest of the values are initialised to 0 */
    obj_metrics->min_size[index] = UINT64_MAX;
    obj_metrics->count++;
    LOG_DEBUG("Added object type at index %d: %s (total types: %zu)\n", 
        index, class_sig, obj_metrics->count);
    return index;
}

static void update_object_allocation_stats(agent_context_t *ctx, const char *class_sig, uint64_t safe_sz)
{
    assert(ctx != NULL);
    assert(class_sig != NULL);

    if (!ctx || !class_sig)
        return;

    int index = find_or_add_object_type(ctx->object_metrics, class_sig);
    if (index >= 0) 
    {
        __atomic_add_fetch(&ctx->object_metrics->allocation_counts[index], 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&ctx->object_metrics->total_bytes[index], safe_sz, __ATOMIC_RELAXED);
        __atomic_add_fetch(&ctx->object_metrics->current_instances[index], 1, __ATOMIC_RELAXED);
        
        /* Update size statistics */
        pthread_mutex_lock(&ctx->samples_lock);
        if (safe_sz < ctx->object_metrics->min_size[index])
            ctx->object_metrics->min_size[index] = safe_sz;

        if (safe_sz > ctx->object_metrics->max_size[index])
            ctx->object_metrics->max_size[index] = safe_sz;
        
        /* Update average size */
        ctx->object_metrics->avg_size[index] = 
            ctx->object_metrics->total_bytes[index] / ctx->object_metrics->allocation_counts[index];
        pthread_mutex_unlock(&ctx->samples_lock);
    }
}

static void export_method_to_shm(agent_context_t *ctx) {
    if (!ctx->shm_ctx || !ctx->metrics) 
        return;
    
    pthread_mutex_lock(&ctx->samples_lock);
    
    for (size_t i = 0; i < ctx->metrics->capacity; i++) {
        if (ctx->metrics->signatures[i]) {
            /* Create clean method data structure */
            cooper_method_data_t method_data = {0};
            
            strncpy(method_data.signature, ctx->metrics->signatures[i], COOPER_MAX_SIGNATURE_LEN - 1);
            method_data.signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';
            
            /* Direct field assignment */
            method_data.call_count = ctx->metrics->call_counts[i];
            method_data.sample_count = ctx->metrics->sample_counts[i];
            method_data.total_time_ns = ctx->metrics->total_time_ns[i];
            method_data.min_time_ns = ctx->metrics->min_time_ns[i];
            method_data.max_time_ns = ctx->metrics->max_time_ns[i];
            method_data.alloc_bytes = ctx->metrics->alloc_bytes[i];
            method_data.peak_memory = ctx->metrics->peak_memory[i];
            method_data.cpu_cycles = ctx->metrics->cpu_cycles[i];
            method_data.metric_flags = ctx->metrics->metric_flags[i];
            
            cooper_shm_write_method_data(ctx->shm_ctx, &method_data);
        }
    }
    
    pthread_mutex_unlock(&ctx->samples_lock);
}

/**
 * Export memory samples to shared memory
 */
static void export_memory_to_shm(agent_context_t *ctx) {
    if (!ctx->shm_ctx || !ctx->app_memory_metrics) 
        return;
    
    pthread_mutex_lock(&ctx->app_memory_metrics->lock);
    
    /* Export latest process memory sample */
    if (ctx->app_memory_metrics->sample_count > 0) {
        size_t latest_idx = (ctx->app_memory_metrics->sample_count - 1) % MAX_MEMORY_SAMPLES;
        
        /* Clean memory data structure */
        cooper_memory_data_t memory_data = {
            .process_memory = ctx->app_memory_metrics->process_memory_sample[latest_idx],
            .thread_id = 0, /* Process-wide */
            .thread_memory = 0
        };
        
        cooper_shm_write_memory_data(ctx->shm_ctx, &memory_data);
    }

    /* Export thread memory samples */
    if (ctx->thread_mem_head != NULL) {
        thread_memory_metrics_t *tm = ctx->thread_mem_head;
        while(tm) {
            if (tm->sample_count > 0) {
                size_t latest_idx = (tm->sample_count - 1) % MAX_MEMORY_SAMPLES;
                
                cooper_memory_data_t memory_data = {
                    .process_memory = 0, /* Not applicable for thread-specific */
                    .thread_id = tm->thread_id,
                    .thread_memory = tm->memory_samples[latest_idx]
                };
                
                cooper_shm_write_memory_data(ctx->shm_ctx, &memory_data);
            }
            tm = tm->next;
        }
    }
    
    pthread_mutex_unlock(&ctx->app_memory_metrics->lock);
}

/**
 * Export object allocation metrics to shared memory
 */
static void export_object_alloc_to_shm(agent_context_t *ctx) {
    if (!ctx->shm_ctx || !ctx->object_metrics) 
        return;
    
    pthread_mutex_lock(&ctx->samples_lock);
    
    for (size_t i = 0; i < ctx->object_metrics->count; i++) {
        if (ctx->object_metrics->class_signatures[i] && 
            ctx->object_metrics->allocation_counts[i] > 0) {
            
            /* Clean object allocation data */
            cooper_object_alloc_data_t alloc_data = {0};
            
            strncpy(alloc_data.class_signature, ctx->object_metrics->class_signatures[i], COOPER_MAX_SIGNATURE_LEN - 1);
            alloc_data.class_signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';
            
            /* Semantic field names */
            alloc_data.allocation_count = ctx->object_metrics->allocation_counts[i];
            alloc_data.current_instances = ctx->object_metrics->current_instances[i];
            alloc_data.total_bytes = ctx->object_metrics->total_bytes[i];
            alloc_data.peak_instances = ctx->object_metrics->peak_instances[i];
            alloc_data.min_size = ctx->object_metrics->min_size[i];
            alloc_data.max_size = ctx->object_metrics->max_size[i];
            alloc_data.avg_size = ctx->object_metrics->avg_size[i];
            
            cooper_shm_write_object_alloc_data(ctx->shm_ctx, &alloc_data);
        }
    }
    
    pthread_mutex_unlock(&ctx->samples_lock);
}

/**
 * Shared memory export thread function
 */
void *shm_export_thread_func(void *arg) {
    agent_context_t *ctx = (agent_context_t *)arg;
    
    LOG_INFO("Shared memory export thread started");
    
    /* TODO move export interval to const */
    while (ctx->shm_export_running) {
        if (ctx->shm_ctx == NULL)
        {
            LOG_DEBUG("Shared mem not available, thread sleeping");
            sleep(2);
            continue;
        }

        /* Clean up entries that CLI has read */
        cooper_shm_cleanup_read_entries(ctx->shm_ctx);
        
        /* Export current metrics */
        export_method_to_shm(ctx);
        
        /* Export memory samples */
        export_memory_to_shm(ctx);

        /* Export object allocation metrics */
        export_object_alloc_to_shm(ctx);
        
        /* Sleep for export interval */
        sleep(2);
    }
    
    LOG_INFO("Shared memory export thread terminated");
    return NULL;
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

    return 0;
}

/**
 *
 *@param ctx Pointer to agent_context_t
 */
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
    
    /* Export application memory samples */
    fprintf(fp, "# Application Memory Metrics\n");
    fprintf(fp, "# Format: timestamp, process_memory_bytes\n");

    /* Lock app memory metrics for thread-safe access */
    pthread_mutex_lock(&ctx->app_memory_metrics->lock);

    /* Export memory samples in chronological order */
    for (size_t i = 0; i < ctx->app_memory_metrics->sample_count; i++) 
    {
        fprintf(fp, "%" PRIu64 ",%" PRIu64 "\n", 
            ctx->app_memory_metrics->timestamps[i],
            ctx->app_memory_metrics->process_memory_sample[i]);
    }

    fprintf(fp, "# ------ \n\n");

    /* Export thread memory metrics next */
    fprintf(fp, "# Thread Memory Metrics\n");
    fprintf(fp, "# Format: thread_id, timestamp, thread_memory_bytes\n");

    /* Find the head of the thread metrics linked list (should be stored in global context) */
    thread_memory_metrics_t *thread_metrics = ctx->thread_mem_head;
    int thread_count = 0;

    /* Iterate through the thread metrics linked list */
    while (thread_metrics) 
    {
        thread_count++;
        fprintf(fp, "# Thread ID: %lld\n", (long long)thread_metrics->thread_id);
        
        for (size_t i = 0; i < thread_metrics->sample_count && i < MAX_MEMORY_SAMPLES; i++) 
        {
            size_t idx;
            if (thread_metrics->sample_count <= MAX_MEMORY_SAMPLES)
                idx = i; /* buffer not full yet so just set idx */
            else
            {
                /* buffer is full we need to start from the oldest entry, 
                this would be the position of the next entry to be written
                */
                size_t oldest_idx = thread_metrics->sample_count % MAX_MEMORY_SAMPLES;
                /* add current pos and wrap around if required */
                idx = (oldest_idx + i) % MAX_MEMORY_SAMPLES;
            }
            
            fprintf(fp, "%" PRId64 ",%" PRIu64 ",%" PRIu64 "\n", 
                thread_metrics->thread_id,
                thread_metrics->timestamps[idx],
                thread_metrics->memory_samples[idx]);
        }
        
        thread_metrics = thread_metrics->next;
    }

    if (thread_count == 0)
        fprintf(fp, "# No thread memory metrics available\n");

    pthread_mutex_unlock(&ctx->app_memory_metrics->lock);

    object_allocation_metrics_t *obj_metrics = ctx->object_metrics;

    if (obj_metrics)
    {
        /* Add object allocation statistics section */
        fprintf(fp, "# Object Allocation Statistics\n");
        fprintf(fp, "# Format: class_signature, allocation_count, total_bytes, current_instances, avg_size, min_size, max_size\n");

        for (size_t i = 0; i < obj_metrics->count; i++) 
        {
            fprintf(fp, "%s,%lu,%lu,%lu,%lu,%lu,%lu\n",
                obj_metrics->class_signatures[i],
                (unsigned long)obj_metrics->allocation_counts[i],
                (unsigned long)obj_metrics->total_bytes[i],
                (unsigned long)obj_metrics->current_instances[i],
                (unsigned long)obj_metrics->avg_size[i],
                (unsigned long)obj_metrics->min_size[i],
                (unsigned long)obj_metrics->max_size[i]);
        }
    }
    else
        fprintf(fp, "# No object allocation metrics available\n");
    
    fprintf(fp, "# ------ \n\n");

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

    /* Add heap stats section before summary */
    fprintf(fp, "# ------ \n\n");

    fprintf(fp, "# Heap Statistics (Top %zu Classes by Memory Usage)\n", ctx->last_heap_stats_count);
    fprintf(fp, "# Format: class_name, instance_count, total_size, avg_size\n");

    if (ctx->last_heap_stats && ctx->last_heap_stats_count > 0) 
    {
        for (size_t i = 0; i < ctx->last_heap_stats_count; i++) 
        {
            class_stats_t *stats = (class_stats_t*)ctx->last_heap_stats->elements[i];
            if (stats && stats->class_name) 
            {
                fprintf(fp, "%s,%llu,%llu,%llu\n",
                    stats->class_name,
                    (unsigned long long)stats->instance_count,
                    (unsigned long long)stats->total_size,
                    (unsigned long long)stats->avg_size);
            }
        }
    }
    else 
    {
        fprintf(fp, "# No heap statistics available\n");
    }

    fprintf(fp, "# ------ \n\n");

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
        for (int i = 0; i < ctx->config.export_interval && ctx->export_running; i++)
            sleep(1);
        
        if (ctx->export_running) 
        {
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
 *
 */
static void sample_thread_mem(agent_context_t *ctx, JNIEnv *jni, uint64_t timestamp)
{
    if (!jni || !ctx)
    {
        LOG_ERROR("Invalid context or JNI environment in sample_thread_mem");
        return;
    }
    
    jobject threadsMap = NULL;
    jobject entrySet = NULL;
    jobjectArray entries = NULL;
    jclass mapClass = NULL;
    jclass setClass = NULL;

    /* Get the getAllStackTraces method */
    jmethodID getAllThreadsMethod = (*jni)->GetStaticMethodID(jni, ctx->java_thread_class, 
        "getAllStackTraces", "()Ljava/util/Map;");
    if (!getAllThreadsMethod) 
    {
        LOG_ERROR("Failed to find getAllStackTraces method\n");
        goto cleanup;
    }
    
    /* Call getAllStackTraces to get all threads */
    threadsMap = (*jni)->CallStaticObjectMethod(jni, ctx->java_thread_class, getAllThreadsMethod);
    if (!threadsMap || (*jni)->ExceptionCheck(jni)) 
    {
        if ((*jni)->ExceptionCheck(jni)) 
        {
            (*jni)->ExceptionClear(jni);
            LOG_ERROR("Exception occurred while calling getAllStackTraces");
        } 
        else 
        {
            LOG_ERROR("Failed to get threads map\n");
        }
        goto cleanup;
    }

    /* Get the entry set from the map */
    mapClass = (*jni)->GetObjectClass(jni, threadsMap);
    if (!mapClass) 
    {
        LOG_ERROR("Failed to get Map class\n");
        goto cleanup;
    }
    
    jmethodID entrySetMethod = (*jni)->GetMethodID(jni, mapClass, "entrySet", "()Ljava/util/Set;");
    if (!entrySetMethod) 
    {
        LOG_ERROR("Failed to find entrySet method\n");
        goto cleanup;
    }
    
    entrySet = (*jni)->CallObjectMethod(jni, threadsMap, entrySetMethod);
    if (!entrySet || (*jni)->ExceptionCheck(jni)) 
    {
        if ((*jni)->ExceptionCheck(jni)) 
        {
            (*jni)->ExceptionClear(jni);
            LOG_ERROR("Exception occurred while calling entrySet");
        } 
        else 
        {
            LOG_ERROR("Failed to get entry set\n");
        }
        goto cleanup;
    }
    
    /* Get the toArray method from Set */
    setClass = (*jni)->GetObjectClass(jni, entrySet);
    if (!setClass) 
    {
        LOG_ERROR("Failed to get Set class\n");
        goto cleanup;
    }

    jmethodID toArrayMethod = (*jni)->GetMethodID(jni, setClass, "toArray", "()[Ljava/lang/Object;");
    if (!toArrayMethod) 
    {
        LOG_ERROR("Failed to find toArray method\n");
        goto cleanup;
    }
    
    entries = (jobjectArray)(*jni)->CallObjectMethod(jni, entrySet, toArrayMethod);
    if (!entries || (*jni)->ExceptionCheck(jni)) 
    {
        if ((*jni)->ExceptionCheck(jni)) 
        {
            (*jni)->ExceptionClear(jni);
            LOG_ERROR("Exception occurred while calling toArray");
        } 
        else 
        {
            LOG_ERROR("Failed to get entries array\n");
        }
        goto cleanup;
    }

    /* Log the number of Java threads found for debugging */
    jsize num_threads = (*jni)->GetArrayLength(jni, entries);
    LOG_DEBUG("Found %d Java threads in getAllStackTraces", num_threads);

    /* Process each java live thread */
    for (int j = 0; j < num_threads; j++) {
        jobject entry = NULL;
        jobject threadObj = NULL;
        jclass entryClass = NULL;
        
        entry = (*jni)->GetObjectArrayElement(jni, entries, j);
        if (!entry) continue;
        
        /* Get the key (Thread object) from the entry */
        entryClass = (*jni)->GetObjectClass(jni, entry);
        if (!entryClass)
            goto local_clean;
        
        jmethodID getKeyMethod = (*jni)->GetMethodID(jni, entryClass, "getKey", 
            "()Ljava/lang/Object;");
        if (!getKeyMethod)
            goto local_clean;
        
        threadObj = (*jni)->CallObjectMethod(jni, entry, getKeyMethod);
        if (!threadObj)
            goto local_clean;
        
        /* Get thread ID */
        jlong thread_id = (*jni)->CallLongMethod(jni, threadObj, ctx->getId_method);
        if ((*jni)->ExceptionCheck(jni)) 
        {
            (*jni)->ExceptionClear(jni);
            goto local_clean;
        }
        
        LOG_DEBUG("Processing Java thread ID: %lld", (long long)thread_id);
        
        /* Get native thread ID */
        pid_t native_tid = get_native_thread_id(ctx->jvmti_env, jni, threadObj);
        if (native_tid == 0) 
        {
            LOG_DEBUG("Could not get native thread ID for Java thread %lld", (long long)thread_id);
            goto local_clean;
        }
        
        /* Sample thread memory */
        uint64_t thread_mem = get_thread_memory(ctx->jvmti_env, jni, threadObj);
        if (thread_mem == 0)
            continue;

        thread_memory_metrics_t *thread_metrics = ctx->thread_mem_head;
        int found = 0;
        
        /* Look for existing metrics for this thread */
        while (thread_metrics) {
            if (thread_metrics->thread_id == thread_id) 
            {
                found = 1;
                break;
            }
            thread_metrics = thread_metrics->next;
        }
        
        /* If not found, create new metrics structure */
        if (!found) 
        {
            arena_t *metrics_arena = ctx->arenas[METRICS_ARENA_ID];
            if (metrics_arena) 
            {
                thread_metrics = arena_alloc(metrics_arena, sizeof(thread_memory_metrics_t));
                if (thread_metrics) 
                {
                    thread_metrics->thread_id = thread_id;
                    thread_metrics->next = ctx->thread_mem_head;
                    ctx->thread_mem_head = thread_metrics;
                    LOG_INFO("Created new thread memory metrics for thread %lld", (long long)thread_id);
                }
            }
        }
        
        /* Store the memory sample */
        if (thread_metrics) 
        {
            size_t idx = thread_metrics->sample_count % MAX_MEMORY_SAMPLES;
            thread_metrics->memory_samples[idx] = thread_mem;
            thread_metrics->timestamps[idx] = timestamp;
            
            if (thread_metrics->sample_count < MAX_MEMORY_SAMPLES)
                thread_metrics->sample_count++;
            
            LOG_DEBUG("Stored memory sample for thread %lld: %llu bytes", (long long)thread_id, (unsigned long long)thread_mem);
        }
        
local_clean:
        /* Clean up local references */
        if (threadObj) (*jni)->DeleteLocalRef(jni, threadObj);
        if (entryClass) (*jni)->DeleteLocalRef(jni, entryClass);
        if (entry) (*jni)->DeleteLocalRef(jni, entry);
    }

cleanup:
    /* Clean up all JNI local references */
    if (entries) (*jni)->DeleteLocalRef(jni, entries);
    if (setClass) (*jni)->DeleteLocalRef(jni, setClass);
    if (entrySet) (*jni)->DeleteLocalRef(jni, entrySet);
    if (mapClass) (*jni)->DeleteLocalRef(jni, mapClass);
    if (threadsMap) (*jni)->DeleteLocalRef(jni, threadsMap);
}

/**
 * 
 */
void *mem_sampling_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;
    LOG_INFO("Memory sampling thread started, interval=%d seconds\n", ctx->config.mem_sample_interval);

    JNIEnv *jni = NULL;
    jvmtiError err;
    jvmtiPhase jvm_phase;
    int mem_thread_attached = 0;

    /* Attach this thread to the JVM to get a JNIEnv */
    jint res = (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void**)&jni, NULL);
    if (res != JNI_OK || jni == NULL)
    {
        LOG_ERROR("Failed to attach memory sampling thread to JVM, error: %d\n", res);
        return NULL;
    }
    
    mem_thread_attached = 1;
    LOG_INFO("Memory sampling thread successfully attached to JVM");

    while (ctx->mem_sampling_running)
    {
        err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
        if (err != JVMTI_ERROR_NONE)
        {
            LOG_ERROR("Error getting the current jvm phase - maybe during shutdown? error %d", err);
            return NULL;
        }

        if (jvm_phase != JVMTI_PHASE_LIVE)
        {
            LOG_INFO("JVM is not in live phase, cannot sample thread memory, current jvm phase: %d", jvm_phase);
            return NULL;
        }

        /* Get current timestamp for this sample */
        uint64_t timestamp = get_current_time_ns();
        
        /* Sample process memory */
        uint64_t process_mem = get_process_memory();
        if (process_mem > 0) 
        {
            pthread_mutex_lock(&ctx->app_memory_metrics->lock);
            
            /* Use circular buffer pattern if we reach maximum samples */
            size_t idx = ctx->app_memory_metrics->sample_count % MAX_MEMORY_SAMPLES;
            ctx->app_memory_metrics->process_memory_sample[idx] = process_mem;
            ctx->app_memory_metrics->timestamps[idx] = timestamp;
            
            if (ctx->app_memory_metrics->sample_count < MAX_MEMORY_SAMPLES)
                ctx->app_memory_metrics->sample_count++;
                
            pthread_mutex_unlock(&ctx->app_memory_metrics->lock);
            
            LOG_DEBUG("Memory sample #%zu: %llu bytes at %llu ns", 
                ctx->app_memory_metrics->sample_count,
                (unsigned long long)process_mem,
                (unsigned long long)timestamp);
        }
        
        /* Sample thread memory for active Java threads */
        sample_thread_mem(ctx, jni, timestamp);
        
        /* Sleep for the configured interval */
        sleep(ctx->config.mem_sample_interval);
    }

    /* Cannot detach thread when not attached.. */
    if (mem_thread_attached)
    {
        /* We cannot detach thread if the jvmPhase is not JVMTI_PHASE_LIVE */
        if ((*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase) == JVMTI_ERROR_NONE && jvm_phase == JVMTI_PHASE_LIVE)
                (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
    }
    
    LOG_INFO("Memory sampling thread terminated\n");
    return NULL;
}

#ifdef ENABLE_DEBUG_LOGS
/**
 * get a param value for a method
 * 
 */
static char *get_parameter_value(arena_t *arena, jvmtiEnv *jvmti, JNIEnv *jni_env, 
    jthread thread, jint param_slot, char param_type)
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
#endif

/**
 * Find the index of a method in the metrics structure
 */
int find_method_index(method_metrics_soa_t *metrics, const char *signature) 
{
    if (!metrics || !signature) return -1;
    
    for (size_t i = 0; i < metrics->count; i++) 
    {
        if (metrics->signatures[i] && strcmp(metrics->signatures[i], signature) == 0)
            return (int)i;
    }
    
    return -1;  /* Not found */
}

/**
 * Finds the index for a method in the metrics array based on filter rules.
 * This is a read-only, non-locking function used during class loading.
 *
 * @return The index into the metrics array if a match is found, otherwise -1.
 */
static int find_method_filter_index(agent_context_t *ctx, const char *class_signature,
                                    const char *method_name, const char *method_signature)
{
    char full_sig[MAX_SIG_SZ];

    /* Check for an exact match first */
    snprintf(full_sig, sizeof(full_sig), "%s %s %s", class_signature, method_name, method_signature);
    int method_index = find_method_index(ctx->metrics, full_sig);
    if (method_index >= 0)
        return method_index;

    /* If no exact match, try a class-level wildcard match */
    snprintf(full_sig, sizeof(full_sig), "%s * *", class_signature);
    method_index = find_method_index(ctx->metrics, full_sig);
    if (method_index >= 0)
        return method_index;

    return -1; /* No matching filter found */
}

/* Caches class and method info using SetTag */
static void cache_class_info(jvmtiEnv *jvmti_env, jclass klass) 
{
    assert(jvmti_env != NULL);
    
    char *class_sig = NULL;
    jvmtiError err = (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);
    if (err != JVMTI_ERROR_NONE || class_sig == NULL) 
        goto deallocate;

    /* Allocate the main class_info struct from the class cache arena */
    class_info_t *info = arena_alloc(global_ctx->arenas[CLASS_CACHE_ARENA_ID], sizeof(class_info_t));
    if (info == NULL) 
        goto deallocate;

    strncpy(info->class_sig, class_sig, sizeof(info->class_sig) - 1);
    info->in_heap_iteration = 0;

    /* Get all methods for the class */
    jint method_count = 0;
    jmethodID *methods = NULL;
    err = (*jvmti_env)->GetClassMethods(jvmti_env, klass, &method_count, &methods);

    if (err != JVMTI_ERROR_NONE)
        goto deallocate;

    if (method_count == 0)
        goto deallocate;

    /* Allocate space for the method info array in the same arena */
    info->methods = arena_alloc(global_ctx->arenas[CLASS_CACHE_ARENA_ID], sizeof(method_info_t) * method_count);
    info->method_count = method_count;

    if (info->methods != NULL) 
    {
        /* Loop through each method and cache its details */
        for (int i = 0; i < method_count; i++) 
        {
            char *method_name = NULL;
            char *method_sig = NULL;
            info->methods[i].method_id = methods[i];

            if ((*jvmti_env)->GetMethodName(jvmti_env, methods[i], &method_name, &method_sig, NULL) == JVMTI_ERROR_NONE) 
            {
                /* Store arena-allocated copies of the names */
                info->methods[i].method_name = arena_strdup(global_ctx->arenas[CLASS_CACHE_ARENA_ID], method_name);
                info->methods[i].method_signature = arena_strdup(global_ctx->arenas[CLASS_CACHE_ARENA_ID], method_sig);

                info->methods[i].sample_index = find_method_filter_index(
                    global_ctx, class_sig, method_name, method_sig);

                (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_name);
                (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_sig);
            }
        }
    }
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)methods);

    /* Set the tag */
    jlong tag = (jlong)(intptr_t)info;
    (*jvmti_env)->SetTag(jvmti_env, klass, tag);

deallocate:
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_sig);
}

/*
 * Method entry callback
 */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method)
{
    UNUSED(jni);
    UNUSED(thread);

    /* Get the declaring class of the method. This is the only JVMTI call needed for lookup. */
    jclass declaring_class;
    jvmtiError err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) 
        return; /* Cannot proceed without the class. */

    /* Get the tag associated with the class, which points to our cached class_info_t struct. */
    jlong tag = 0;

    /* This GetTag call is extremely fast. */
    err = (*jvmti)->GetTag(jvmti, declaring_class, &tag);
    if (err != JVMTI_ERROR_NONE || tag == 0) 
    {
        /* This can happen for classes loaded before the agent was attached.
        We simply ignore them to keep this path fast. */
        return;
    }
    class_info_t *info = (class_info_t*)(intptr_t)tag;

    /* Find the specific method's cached info in the class's method list.
    For extreme performance, this linear scan could be replaced with a binary search
    or a micro-hashtable if the methods array was sorted by method_id at class load time. */
    method_info_t *method_info = NULL;
    for (uint32_t i = 0; i < info->method_count; i++) 
    {
        if (info->methods[i].method_id == method) 
        {
            method_info = &info->methods[i];
            break;
        }
    }

    /* We either didn't find the method (should be rare) or it's not one we're configured to sample. */
    if (method_info == NULL || method_info->sample_index < 0) 
        return;

    /* We found a method to track. Atomically increment its total call count. */
    uint64_t current_calls = __atomic_add_fetch(&global_ctx->metrics->call_counts[method_info->sample_index], 1, __ATOMIC_RELAXED);
    int sample_rate = global_ctx->metrics->sample_rates[method_info->sample_index]; /* Read-only after init */

    /* Decide whether to sample this specific call based on the rate. */
    if ((current_calls % sample_rate) != 0)
        return; /* Don't sample this call. */

    /* This call will be sampled. Proceed with creating the method_sample_t. */
    thread_context_t *tc = get_thread_local_context();
    if (!tc) return;

    arena_t *arena = global_ctx->arenas[SAMPLE_ARENA_ID];
    if (!arena) return;

    method_sample_t *sample = init_method_sample(arena, method_info->sample_index, method);
    if (!sample) return;

    /* Push the sample onto the thread's stack. */
    sample->parent = tc->sample;
    tc->sample = sample;
    tc->stack_depth++;

    LOG_DEBUG("[ENTRY] Sampling method %s.%s\n", info->class_sig, method_info->method_name);
}

/*
 * Method exit callback
 */
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value)
{
    UNUSED(jni);
    UNUSED(thread);
    UNUSED(was_popped_by_exception);
    UNUSED(return_value);
    
#ifndef ENABLE_DEBUG_LOGS
    UNUSED(jvmti);
#endif

    /* Get thread-local context */
    thread_context_t *context = get_thread_local_context();

    /* Cannot do anything without the thread_context */
    if (!context) return;

    if (!context->sample || context->sample->method_index < 0)
    {
        LOG_DEBUG("[method_exit_callback] context:%p context->sample:%p", context, context->sample);
    }
    
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

    if ((flags & METRIC_FLAG_MEMORY) != 0) 
    {
        LOG_DEBUG("sampling memory for %d\n", target->method_index);
         /* JVM heap allocations during method execution */
        memory_delta = target->current_alloc_bytes;
    }
    
    if ((flags & METRIC_FLAG_CPU) != 0) 
    {
        uint64_t end_cpu = cycles_end();

        if (end_cpu > target->start_cpu)
            cpu_delta = end_cpu - target->start_cpu;
        else
            LOG_DEBUG("Invalid CPU cycles: end=%llu, start=%llu", (unsigned long long)end_cpu, (unsigned long long)target->start_cpu);
    }
    
    /* Record the metrics */
    record_method_execution(global_ctx, target->method_index, exec_time, memory_delta, cpu_delta);

#ifdef ENABLE_DEBUG_LOGS
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaringClass;
    jvmtiError err;

    /* Get method details for logging */
    if (flags != 0)
    {
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
#endif
}

/**
 * Exception callback
 */
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location)
{
    UNUSED(jvmti_env);
    UNUSED(jni_env);
    UNUSED(thread);
    UNUSED(method);
    UNUSED(location);
    UNUSED(exception);
    UNUSED(catch_method);
    UNUSED(catch_location);

    /* TODO do something more useful with exception callbacks - just logging at the moment is noise */
#ifdef ENABLE_DEBUG_LOGS
    UNUSED(location);
    UNUSED(catch_location);
    
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

        arena_t *arena = global_ctx->arenas[EXCEPTION_ARENA_ID];
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
            char *param_val = get_parameter_value(arena, jvmti_env, jni_env, thread, slot, param_type);

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
#endif
}

static void JNICALL object_alloc_callback(jvmtiEnv *jvmti_env, JNIEnv *jni, jthread thread, jobject object, jclass klass, jlong size)
{
    UNUSED(jni);
    UNUSED(thread);
    UNUSED(object);
    
    /* Buffer for class signature */
    char *class_sig = NULL;
        
    /* Get cached class signature */
    if (get_cached_class_signature(jvmti_env, klass, &class_sig) != COOPER_OK) 
    {
        LOG_DEBUG("[object_alloc_callback] Unable to get class signature for object tracking\n");
        return;
    }

    /* Convert the jlong (signed) to a uint64_t as we store our stats unsigned */
    uint64_t safe_sz = (size >= 0) ? (uint64_t)size : 0;
    /* Update the global allocation stats */
    update_object_allocation_stats(global_ctx, class_sig, safe_sz);

    /* Get thread-local context to prevent re-entrancy */
    thread_context_t *context = get_thread_local_context();
    if (!context)
    {
        LOG_DEBUG("[object_alloc_callback] No context\n");
        return;
    }
    
    method_sample_t *sample = context->sample;
    if (!sample) 
    {
        LOG_DEBUG("[object_alloc_callback] No sample\n");
        return;
    }

    /* Check if memory metrics are enabled for this method */
    if (sample->method_index < 0 || 
        (size_t)sample->method_index >= global_ctx->metrics->count || 
        !(global_ctx->metrics->metric_flags[sample->method_index] & METRIC_FLAG_MEMORY))
        return;

    /* Add allocation to the current method being sampled */
    sample->current_alloc_bytes += safe_sz;

    LOG_DEBUG("Allocation: %lld bytes for method_index %d, total: %lld, allocated object of class: %s, size: %lld", 
        safe_sz, sample->method_index, (long long)sample->current_alloc_bytes, class_sig, safe_sz);
}

static void JNICALL class_load_callback(jvmtiEnv *jvmti_env, JNIEnv* jni_env, 
                                        jthread thread, jclass klass)
{
    UNUSED(jni_env);
    UNUSED(thread);
    
    cache_class_info(jvmti_env, klass);
}

static void JNICALL thread_end_callback(jvmtiEnv *jvmti, JNIEnv *jni, jthread thread)
{
    UNUSED(jvmti);

    /* Check we can do anything here before looking up thread context */
    if (!thread)
        return;

    if (!global_ctx->getId_method)
        return;

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

    jlong thread_id = (*jni)->CallLongMethod(jni, thread, global_ctx->getId_method);

    /* Remove from our mapping table */
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

/* Comparison function for class stats (by total_size) */
static int class_stats_compare(const void *a, const void *b) 
{
    const class_stats_t *stats_a = (const class_stats_t*)a;
    const class_stats_t *stats_b = (const class_stats_t*)b;
    
    if (stats_a->total_size < stats_b->total_size) return -1;
    if (stats_a->total_size > stats_b->total_size) return 1;
    return 0;
}

/* Enhanced find_or_create_stats with additional safety checks */
static class_stats_t *find_or_create_stats(heap_iteration_context_t *ctx, const char *class_sig)
{
    
    assert(ctx != NULL);
    assert(ctx->class_table != NULL);
    assert(class_sig != NULL);

    /* Additional validation */
    if (!class_sig || class_sig[0] == '\0')
    {
        LOG_DEBUG("Skipping null or empty class_sig");
        return NULL;
    }

    /* Try to find existing stats using API */
    class_stats_t *stats = (class_stats_t*)ht_get(ctx->class_table, class_sig);
    if (stats) 
    {
        /* Found existing entry */
        return stats;
    }

    /* Check load factor before creating new entry */
    if (ht_get_load(ctx->class_table) >= 0.75) 
    {
        LOG_ERROR("Hash table load factor exceeded");
        return NULL;
    }

    /* Create new stats entry */
    stats = arena_alloc(ctx->arena, sizeof(class_stats_t));
    if (!stats) 
    {
        LOG_ERROR("Failed to allocate class stats");
        return NULL;
    }

    /* Initialize stats */
    stats->instance_count = 0;
    stats->total_size = 0;
    stats->avg_size = 0;
    stats->class_name = NULL; /* Will be set later if needed */

    /* Add to hashtable using API */
    if (!ht_put(ctx->class_table, class_sig, stats)) 
    {
        LOG_ERROR("Failed to add class stats to hashtable");
        return NULL;
    }

    LOG_DEBUG("Created new hash entry for class '%s' (load: %.2f)", 
                class_sig, ht_get_load(ctx->class_table));
    return stats;
}

/* Robust heap object callback with enhanced error handling */
static jint JNICALL heap_object_callback(jvmtiHeapReferenceKind reference_kind,
                               const jvmtiHeapReferenceInfo *reference_info,
                               jlong class_tag,
                               jlong referrer_class_tag,
                               jlong size,
                               jlong *tag_ptr,
                               jlong *referrer_tag,
                               jint length,
                               void *user_data)
{
    UNUSED(reference_kind);
    UNUSED(reference_info);
    UNUSED(referrer_class_tag);
    UNUSED(tag_ptr);
    UNUSED(referrer_tag);
    UNUSED(length);

    /* No-op */
    if (class_tag == 0)
        return JVMTI_VISIT_OBJECTS;
    
    if (size < 0) 
    {
        LOG_DEBUG("Negative object size %ld for class_tag %ld", size, class_tag);
        return JVMTI_VISIT_OBJECTS;
    }
    
    if (!user_data) 
    {
        LOG_ERROR("Null user_data in heap callback");
        return JVMTI_VISIT_ABORT;
    }

    heap_iteration_context_t *ctx = (heap_iteration_context_t*)user_data;
    
    /* Validate context */
    if (!ctx->class_table) 
    {
        LOG_ERROR("Invalid context in heap callback");
        return JVMTI_VISIT_ABORT;
    }

    /* class_tag should be a pointer to class_info_t struct */
    class_info_t *info = (class_info_t*)(intptr_t)class_tag;
    if (!info->in_heap_iteration) 
        return JVMTI_VISIT_OBJECTS;

    class_stats_t *stats = find_or_create_stats(ctx, info->class_sig);
    
    if (!stats)
        return JVMTI_VISIT_OBJECTS;

    /* Overflow protection for counters */
    if (stats->instance_count == UINT64_MAX) 
    {
        LOG_WARN("Instance count overflow for class_tag %ld", class_tag);
        return JVMTI_VISIT_OBJECTS;
    }
    
    uint64_t safe_size = (uint64_t)size;  /* Convert after validation */
    if (stats->total_size > UINT64_MAX - safe_size) 
    {
        LOG_WARN("Total size overflow for class_tag %ld", class_tag);
        return JVMTI_VISIT_OBJECTS;
    }
    
    stats->instance_count++;
    stats->total_size += safe_size;
    
    /* Safe average calculation */
    if (stats->instance_count > 0)
        stats->avg_size = stats->total_size / stats->instance_count;
    
    return JVMTI_VISIT_OBJECTS;
}

/* Improved hashtable sizing with better limits */
static size_t calculate_hashtable_size(int class_count) 
{
    /* Defensive bounds checking - check negative first */
    if (class_count <= 0) 
    {
        LOG_WARN("Invalid class count (%d), using minimum hash size of %d", class_count, MIN_HASH_SIZE);
        return MIN_HASH_SIZE;
    }

    /* Now safe to cast to unsigned for overflow check */
    size_t class_count_unsigned = (size_t)class_count;

    /* Use load factor of 0.6 for better performance, with overflow protection */
    size_t estimated_size;
    if (class_count_unsigned > SIZE_MAX / 2) 
    {
        LOG_WARN("Class count too large, capping hash table size to %d", MAX_HASH_SIZE);
        estimated_size = MAX_HASH_SIZE;
    } 
    else 
        estimated_size = (size_t)(class_count_unsigned * 1.7); /* Account for heap growth */
    
    if (estimated_size < MIN_HASH_SIZE) 
    {
        estimated_size = MIN_HASH_SIZE;
    } 
    else if (estimated_size > MAX_HASH_SIZE) 
    {
        LOG_WARN("Capping hash table size from %zu to %zu for safety", estimated_size, MAX_HASH_SIZE);
        estimated_size = MAX_HASH_SIZE;
    }
    
    LOG_DEBUG("Calculated hash table size: %zu for %d classes", estimated_size, class_count_unsigned);
    return estimated_size;
}

/* Fully robust heap statistics collection maintaining all safety checks */
static void collect_heap_statistics(jvmtiEnv *jvmti, JNIEnv *env) 
{
    arena_t *scratch_arena = global_ctx->arenas[SCRATCH_ARENA_ID];
    if (!scratch_arena) 
    {
        LOG_ERROR("Failed to find scratch arena");
        return;
    }

    /* Reset scratch arena to reclaim previous allocations */
    arena_reset(scratch_arena);

    /* Clear previous heap stats as these are now invalid */
    global_ctx->last_heap_stats = NULL;
    global_ctx->last_heap_stats_count = 0;

    // TODO move to config
    const size_t TOP_N = 20;
    
    /* Get loaded classes with error handling */
    int class_count;
    jclass *classes;
    jvmtiError err = (*jvmti)->GetLoadedClasses(jvmti, &class_count, &classes);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetLoadedClasses failed: %d", err);
        return;
    }
    
    /* Validate class count */
    if (class_count <= 0) 
    {
        LOG_WARN("No classes found for heap statistics");
        goto cleanup_classes;
    }
    
    LOG_INFO("Collecting heap statistics for %d loaded classes", class_count);

    /* Create min heap with error checking */
    min_heap_t *heap = min_heap_create(scratch_arena, TOP_N, class_stats_compare);
    if (!heap) 
    {
        LOG_ERROR("Failed to create min heap");
        goto cleanup_classes;
    }
    
    /* Create generic hashtable for class statistics */
    size_t hash_size = calculate_hashtable_size(class_count);
    hashtable_t *class_ht = ht_create(scratch_arena, hash_size, 0.75);
    if (!class_ht) 
    {
        LOG_ERROR("Failed to create class generic hashtable");
        goto cleanup_classes;
    }

    /* Set up iteration context with validation */
    heap_iteration_context_t ctx = {
        .env = env,
        .jvmti = jvmti,
        .arena = scratch_arena,
        .class_table = class_ht
    };
    
    /* Validate context before proceeding */
    if (!ctx.env || !ctx.jvmti || !ctx.arena || !ctx.class_table) {
        LOG_ERROR("Invalid iteration context");
        goto cleanup_classes;
    }
    
    /* Tag classes for heap iteration */
    for (int i = 0; i < class_count; i++) 
    {
        jlong tag = 0;
        (*jvmti)->GetTag(jvmti, classes[i], &tag);
        
        if (tag != 0) {
            class_info_t *info = (class_info_t*)(intptr_t)tag;
            info->in_heap_iteration = 1;
        }
    }
    
    /* Use centralized heap callbacks */
    LOG_INFO("Starting heap iteration (hashtable size: %zu)", hash_size);
    err = (*jvmti)->FollowReferences(jvmti, 0, NULL, NULL, &global_ctx->callbacks.heap_callbacks, &ctx);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Heap iteration failed: %d", err);
        goto cleanup_tags;
    }
    
    LOG_INFO("Heap iteration completed, processing %zu unique classes", ctx.class_table->count);
    
    /* Process hashtable results into top-N heap with bounds checking */
    size_t processed = 0;
    
    for (size_t i = 0; i < ctx.class_table->capacity && processed < ctx.class_table->count; i++) 
    {
        ht_entry_t *entry = &ctx.class_table->entries[i];
        
        /* CRITICAL: Check if entry is occupied before accessing value */
        if (entry->state != HT_OCCUPIED || !entry->value)
            continue; /* Skip empty slots */
        
        class_stats_t *stats = (class_stats_t *)entry->value;
        if (stats->instance_count > 0) 
        {
            processed++;
            
            /* Only resolve names for potential top-N entries */
            if (heap->size < TOP_N || 
                stats->total_size > ((class_stats_t *)heap->elements[0])->total_size) 
            {
                class_stats_t *heap_entry = arena_alloc(scratch_arena, sizeof(class_stats_t));
                if (!heap_entry) 
                {
                    LOG_WARN("Failed to allocate heap entry %zu", i);
                    continue;
                }
                
                /* Copy stats */
                *heap_entry = *stats;
                heap_entry->class_name = arena_strdup(scratch_arena, entry->key);
                if (!heap_entry->class_name)
                    continue;
                
                /* Insert into min heap */
                if (!min_heap_insert_or_replace(heap, heap_entry)) 
                {
                    LOG_DEBUG("Failed to insert into heap (likely not top-N)");
                } else {
                    LOG_DEBUG("Added to heap: %s (%llu instances, %llu bytes)", 
                        heap_entry->class_name, 
                        (unsigned long long)heap_entry->instance_count, 
                        (unsigned long long)heap_entry->total_size);
                }
            }
        }
    }
    
    LOG_INFO("Processed %zu classes, top heap size: %zu", processed, heap->size);
    
    global_ctx->last_heap_stats = heap;
    global_ctx->last_heap_stats_count = heap->size;
    global_ctx->last_heap_stats_time = get_current_time_ns();
    LOG_DEBUG("Stored heap statistics: %zu classes at time %llu", 
                heap->size, (unsigned long long)global_ctx->last_heap_stats_time);

    
cleanup_tags:
    /* Clean up class tags */
    for (int i = 0; i < class_count; i++) 
    {
        jlong tag = 0;
        (*jvmti)->GetTag(jvmti, classes[i], &tag);
        
        if (tag != 0) 
        {
            class_info_t *info = (class_info_t*)(intptr_t)tag;
            info->in_heap_iteration = 0;
        }
    }
    
cleanup_classes:
    (*jvmti)->Deallocate(jvmti, (unsigned char*)classes);
}

/* Heap stats collection thread func */
void *heap_stats_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;
    LOG_INFO("Heap statistics thread started, interval=60 seconds\n");
    
    JNIEnv *jni = NULL;
    jvmtiError err;
    jvmtiPhase jvm_phase;
    int heap_thread_attached = 0;
    
    /* Attach this thread to the JVM to get a JNIEnv */
    jint res = (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void**)&jni, NULL);
    if (res != JNI_OK || jni == NULL)
    {
        LOG_ERROR("Failed to attach heap statistics thread to JVM, error: %d\n", res);
        return NULL;
    }
    
    heap_thread_attached = 1;
    LOG_INFO("Heap statistics thread successfully attached to JVM");
    
    //TODO extract sleep interval to config
    while (ctx->heap_stats_running)
    {
        err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
        if (err != JVMTI_ERROR_NONE)
        {
            LOG_ERROR("Error getting JVM phase in heap stats thread: %d", err);
            // goto cleanup;
            sleep(10);
            continue;
        }

        if (jvm_phase != JVMTI_PHASE_LIVE)
        {
            LOG_INFO("JVM not in live phase, skipping heap statistics collection");
            sleep(10);
            continue;
        }
        
        /* Collect heap statistics */
        LOG_INFO("Heap statistics collection starting...");
        collect_heap_statistics(ctx->jvmti_env, jni);
        
        /* Sleep for 60 seconds between collections */
        sleep(60);
    }
    
    /* Detach from JVM if we were attached and JVM is still live */
    if ((*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase) == JVMTI_ERROR_NONE && jvm_phase == JVMTI_PHASE_LIVE)
    {
        if (heap_thread_attached)
            (*ctx->jvm)->DetachCurrentThread(ctx->jvm);
    }
    
    LOG_INFO("Heap statistics thread terminated\n");
    return NULL;
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
    arena_t *arena = ctx->arenas[METRICS_ARENA_ID];
    if (!arena) 
    {
        LOG_DEBUG("Could not find metrics arena\n");
        return -1;
    }
    index = metrics->count;

    /* As the values are guaranteed to be 0 by the initial allocation, no need to set every value here */
    metrics->signatures[index] = arena_strdup(arena, signature);
    metrics->sample_rates[index] = sample_rate;
    metrics->min_time_ns[index] = UINT64_MAX;
    metrics->metric_flags[index] = flags;
    metrics->count++;
    LOG_DEBUG("Added new method at index %d, total methods: %zu\n", index, metrics->count);
    return index;
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
 * @return          COOPER_OK on success, COOPER_ERR on failure
 */
int load_config(agent_context_t *ctx, const char *cf)
{
    assert(ctx != NULL);
    
    if (!ctx) 
        return COOPER_ERR;
    
    arena_t *config_arena = ctx->arenas[CONFIG_ARENA_ID];
    if (!config_arena) 
    {
        LOG_ERROR("Config arena not found\n");
        return COOPER_ERR;
    }
    
    cooper_config_t config;
    if (config_parse(config_arena, cf, &config) != 0) 
    {
        LOG_ERROR("Failed to parse configuration\n");
        return COOPER_ERR;
    }
    
    /* Apply configuration to agent context */
    ctx->config.rate = config.default_sample_rate;
    ctx->config.sample_file_path = config.sample_file_path;
    ctx->config.export_method = config.export_method;
    ctx->config.export_interval = config.export_interval;
    ctx->config.mem_sample_interval = config.mem_sample_interval;
    ctx->config.num_filters = 0; /* We'll track this as we add methods */
    
    /* Convert filters to metrics entries */
    for (size_t i = 0; i < config.num_filters; i++) 
    {
        method_filter_entry_t *filter = &config.filters[i];
        
        /* Build full signature for matching */
        char full_sig[1024];
        int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", 
                             filter->class_signature, filter->method_name, filter->method_signature);
        
        if (written < 0 || written >= (int)sizeof(full_sig)) 
        {
            LOG_ERROR("Method signature too long: %s:%s:%s\n", 
                filter->class_signature, filter->method_name, filter->method_signature);
            continue;
        }
        
        /* Add to metrics structure */
        int method_index = add_method_to_metrics(ctx, full_sig, filter->sample_rate, filter->metric_flags);
        if (method_index < 0) 
        {
            LOG_ERROR("Failed to add method filter: %s\n", full_sig);
            continue;
        }
        
        ctx->config.num_filters++;
    }
    
    return COOPER_OK;
}

/**
 * Helper function to initialize the metrics Struct-of-Arrays structure
 * 
 * @param arena pointer to arena_t to allocate from
 * @param initial_capacity size_t of capacity
 * 
 * @return pointer to method_metrics_soa_t or NULL if allocation fails
 */
method_metrics_soa_t *init_method_metrics(arena_t *arena, size_t initial_capacity) 
{
    assert(arena != NULL);

    method_metrics_soa_t *metrics = arena_alloc_aligned(arena, sizeof(method_metrics_soa_t), CACHE_LINE_SZ);
    if (!metrics) return NULL;
    
    metrics->capacity = initial_capacity;
    
    /* arena_alloc zeroes memory — no need for manual memset */
    metrics->signatures = arena_alloc_aligned(arena, initial_capacity * sizeof(char*), CACHE_LINE_SZ);
    metrics->sample_rates = arena_alloc_aligned(arena, initial_capacity * sizeof(int), CACHE_LINE_SZ);
    metrics->call_counts = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->sample_counts = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->total_time_ns = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->min_time_ns = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->max_time_ns = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->alloc_bytes = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->peak_memory = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->cpu_cycles = arena_alloc_aligned(arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
    metrics->metric_flags = arena_alloc_aligned(arena, initial_capacity * sizeof(unsigned int), CACHE_LINE_SZ);
    
    /* Check if all allocations succeeded */
    if (!metrics->signatures || !metrics->sample_rates || !metrics->call_counts ||
        !metrics->sample_counts || !metrics->total_time_ns || !metrics->min_time_ns ||
        !metrics->max_time_ns || !metrics->alloc_bytes || !metrics->peak_memory ||
        !metrics->cpu_cycles || !metrics->metric_flags) {
        return NULL;
    }

    /* Set min_time_ns to maximum value initially */
    for (size_t i = 0; i < initial_capacity; i++)
        metrics->min_time_ns[i] = UINT64_MAX;
    
    return metrics;
}

static int precache_loaded_classes(jvmtiEnv *jvmti_env)
{
    int class_count;
    jclass *classes;
    jvmtiError err = (*jvmti_env)->GetLoadedClasses(jvmti_env, &class_count, &classes);
    
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("GetLoadedClasses failed: %d", err);
        return COOPER_ERR;
    }

    if (classes == NULL)
    {
        LOG_ERROR("GetLoadedClasses returned NULL class list");
        return COOPER_ERR;
    }

    LOG_INFO("Pre-caching %d loaded classes", class_count);
    
    for (int i = 0; i < class_count; i++) 
    {
        /* Check if already tagged */
        jlong existing_tag = 0;
        (*jvmti_env)->GetTag(jvmti_env, classes[i], &existing_tag);
        
        if (existing_tag > 0)
            continue;
        
        cache_class_info(jvmti_env, classes[i]);
    }
    
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)classes);
    LOG_INFO("Completed pre-caching of loaded classes");
    return COOPER_OK;
}

/**
 * Callback to execute any code after the JVM has completed initialisation (after Agent_OnLoad)
 */
static void JNICALL vm_init_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread)
{
    UNUSED(thread);
    
    if (jni_env == NULL)
    {
        LOG_ERROR("No jni environment");
        exit(1);
    }

    /* Find and cache Thread class */
    jclass local_thread_class = (*jni_env)->FindClass(jni_env, "java/lang/Thread");

    if (local_thread_class == NULL)
    {
        LOG_ERROR("Failed to find Thread class");
        goto error;
    }

    /* Create a global reference to keep the class from being unloaded */
    global_ctx->java_thread_class = (*jni_env)->NewGlobalRef(jni_env, local_thread_class);

    if (global_ctx->java_thread_class == NULL)
    {
        LOG_ERROR("Failed to create global reference for Thread class");
        goto error;
    }

    /* Cache the method ID */
    global_ctx->getId_method = (*jni_env)->GetMethodID(jni_env, global_ctx->java_thread_class, "getId", "()J");

    if (global_ctx->getId_method == NULL) 
    {
        LOG_ERROR("Failed to get Thread.getId method ID");
        goto error;
    }
    
    /* Release local reference */
    (*jni_env)->DeleteLocalRef(jni_env, local_thread_class);
    LOG_INFO("Successfully initialized Thread class and getId method");

    if (precache_loaded_classes(jvmti_env) != COOPER_OK)
    {
        LOG_ERROR("Unable to precache loaded classes");
        goto error;
    }

    /* Start export thread now that JVM is initialized */
    global_ctx->export_running = 1;
    if (start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != 0)
    {
        LOG_ERROR("Failed to start export thread - unable to continue");
        goto error;
    }

    /* Initialize and start shared memory export if available */
    if (global_ctx->shm_ctx != NULL && cooper_shm_init_agent(global_ctx->shm_ctx) == 0) 
    {
        global_ctx->shm_export_running = 1;
        if (start_thread(&global_ctx->shm_export_thread, &shm_export_thread_func, "shm-export", global_ctx) != 0) 
        {
            LOG_ERROR("Failed to start shared memory export thread");
            goto error;
        }
        LOG_INFO("Shared memory export thread started");
    }

    /* Init the memory sampling */
    global_ctx->mem_sampling_running = 1;
    if (start_thread(&global_ctx->mem_sampling_thread, &mem_sampling_thread_func, "mem-sampling", global_ctx) != 0)
    {
        LOG_ERROR("Failed to start memory sampling thread - unable to continue");
        goto error;
    }

    global_ctx->heap_stats_running = 1;
    if (start_thread(&global_ctx->heap_stats_thread, &heap_stats_thread_func, "heap-stats", global_ctx) != 0)
    {
        LOG_ERROR("Failed to start heap statistics thread - unable to continue");
        goto error;
    }

    LOG_INFO("Successfully completed vm_init_callback");
    return;

error:
    /* 
      Safe to call these even if the jobject references are null
      https://docs.oracle.com/en/java/javase/23/docs//specs/jni/functions.html#deleteglobalref
    */
    (*jni_env)->DeleteLocalRef(jni_env, local_thread_class);
    (*jni_env)->DeleteGlobalRef(jni_env, global_ctx->java_thread_class);
    /* In all cases if we reach here we want to exit as the environment is incorrect */
    exit(1);
}

static int init_jvm_capabilities(agent_context_t *ctx)
{
    assert(ctx != NULL);

    if (!ctx) return COOPER_ERR;

    jvmtiCapabilities capabilities;
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
        return COOPER_ERR;
    }

    /* Set event callbacks */
    memset(&ctx->callbacks.event_callbacks, 0, sizeof(ctx->callbacks.event_callbacks));
    ctx->callbacks.event_callbacks.MethodEntry = &method_entry_callback;
    ctx->callbacks.event_callbacks.MethodExit = &method_exit_callback;
    ctx->callbacks.event_callbacks.Exception = &exception_callback;
    ctx->callbacks.event_callbacks.VMObjectAlloc = &object_alloc_callback;
    ctx->callbacks.event_callbacks.ThreadEnd = &thread_end_callback;
    ctx->callbacks.event_callbacks.VMInit = &vm_init_callback;
    // ctx->callbacks.event_callbacks.ClassLoad = &class_load_callback;
    ctx->callbacks.event_callbacks.ClassPrepare = &class_load_callback;

    /* Set heap callbacks */
    memset(&ctx->callbacks.heap_callbacks, 0, sizeof(ctx->callbacks.heap_callbacks));
    ctx->callbacks.heap_callbacks.heap_reference_callback = heap_object_callback;

    err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &ctx->callbacks.event_callbacks, sizeof(ctx->callbacks.event_callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("SetEventCallbacks failed with error %d\n", err);
        return COOPER_ERR;
    }

    /* The events we want to monitor */
    jvmtiEvent events[] = 
    {
        JVMTI_EVENT_METHOD_ENTRY,
        JVMTI_EVENT_METHOD_EXIT,
        JVMTI_EVENT_EXCEPTION,
        JVMTI_EVENT_EXCEPTION_CATCH,
        JVMTI_EVENT_VM_OBJECT_ALLOC,
        JVMTI_EVENT_THREAD_END,
        JVMTI_EVENT_VM_INIT,
        JVMTI_EVENT_CLASS_LOAD
    };

    for (size_t i = 0; i < sizeof(events)/sizeof(events[0]); ++i) {
        err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, events[i], NULL);
        if (err != JVMTI_ERROR_NONE) 
        {
            LOG_ERROR("SetEventNotificationMode for event %d failed with error %d\n", events[i], err);
            return COOPER_ERR;
        }
    }

    return COOPER_OK; /* Success */
}

/**
 * Cleanup state
 * 
 * @param ctx Pointer to an agent_context_t
 */
static void cleanup(agent_context_t *ctx)
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

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    UNUSED(reserved);
    
    /* Allocate and initialize the agent context */
    global_ctx = calloc(1, sizeof(agent_context_t));
    if (!global_ctx) 
    {
        printf("Failed to allocate agent context\n");
        return JNI_ERR;
    }
    global_ctx->config.rate = 1;
    global_ctx->config.export_interval = 60;
    global_ctx->config.mem_sample_interval = 1;
    pthread_mutex_init(&global_ctx->samples_lock, NULL);

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

    if (options && strstr(options, "loglevel=debug"))
        current_log_level = LOG_LEVEL_DEBUG;
    
    log_q_t *log_queue = malloc(sizeof(log_q_t));

    /* 
      We initialise all the arenas we need in this function and we
      destroy all the arenas in the corresponding Agent_OnUnload
    */

    /* Create each arena from the configuration table */
    for (size_t i = 0; i < ARENA_ID__LAST; i++) 
    {
        arena_t *arena = arena_init(arena_configs[i].name, 
            arena_configs[i].size, arena_configs[i].block_count);
        
        if (!arena) 
        {
            printf("Failed to create %s with id: %ld\n", arena_configs[i].name, arena_configs[i].id);
            return JNI_ERR;
        }

        global_ctx->arenas[arena_configs[i].id] = arena;
    }

    /* Init logging after all arenas are created */
    arena_t *log_arena = global_ctx->arenas[LOG_ARENA_ID];
    if (!log_arena) 
    {
        printf("Log arena not found\n");
        return JNI_ERR;
    }

    /* We start the logging thread as we initialise the system now */
    if (init_log_system(log_queue, log_arena, global_ctx->log_file) != COOPER_OK)
    {
        cleanup(global_ctx);
        return JNI_ERR;
    }

    arena_t *class_cache_arena = global_ctx->arenas[CLASS_CACHE_ARENA_ID];
    if (!class_cache_arena) 
    {
        LOG_ERROR("Cache arena not found\n");
        return JNI_ERR;
    }

    /* Initialize metrics after all arenas are created */
    arena_t *metrics_arena = global_ctx->arenas[METRICS_ARENA_ID];
    if (!metrics_arena) 
    {
        LOG_ERROR("Metrics arena not found\n");
        return JNI_ERR;
    }

    /* TODO create const for initial_capacity at some point */
    size_t initial_capacity = 256;
    global_ctx->metrics = init_method_metrics(metrics_arena, initial_capacity);
    if (!global_ctx->metrics) 
    {
        LOG_ERROR("Failed to initialize metrics structure\n");
        return JNI_ERR;
    }

    LOG_DEBUG("Metrics arena usage before object init: %zu / %zu bytes\n", metrics_arena->used, metrics_arena->total_sz);

    /* Add object allocation metrics initialization */
    global_ctx->object_metrics = init_object_allocation_metrics(metrics_arena, MAX_OBJECT_TYPES);
    if (!global_ctx->object_metrics) 
    {
        LOG_ERROR("Failed to initialize object allocation metrics structure\n");
        return JNI_ERR;
    }

    LOG_DEBUG("Metrics arena usage after object init: %zu / %zu bytes\n", metrics_arena->used, metrics_arena->total_sz);

    global_ctx->app_memory_metrics = arena_alloc(metrics_arena, sizeof(app_memory_metrics_t));
    if (!global_ctx->app_memory_metrics)
    {
        LOG_ERROR("Failed to allocate memory for app_memory_metrics\n");
        return JNI_ERR;
    }
    pthread_mutex_init(&global_ctx->app_memory_metrics->lock, NULL);
    
    /* Initialize shared memory */
    arena_t *config_arena = global_ctx->arenas[CONFIG_ARENA_ID];
    if (!config_arena) 
    {
        LOG_ERROR("Config arena not found\n");
        return JNI_ERR;
    }

    global_ctx->shm_ctx = arena_alloc(config_arena, sizeof(cooper_shm_context_t));
    if (!global_ctx->shm_ctx) 
    {
        LOG_ERROR("Failed to allocate shared memory context");
        return JNI_ERR;
    }

    /* Grab a copy of the JVM pointer */
    global_ctx->jvm = vm;

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || global_ctx->jvmti_env == NULL) 
    {
        LOG_ERROR("Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    /* Now we have logging configured, load config */
    if (load_config(global_ctx, "./trace.ini") != COOPER_OK)
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

    if (init_jvm_capabilities(global_ctx) != COOPER_OK)
        return JNI_ERR;

    LOG_INFO("JVMTI Agent Loaded.\n");
    return JNI_OK;
}

/**
 * JVMTI Agent Unload Function
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    if (global_ctx) 
    {
        /* Signal ALL threads to stop BEFORE waiting */
        global_ctx->export_running = 0;
        global_ctx->mem_sampling_running = 0;
        global_ctx->heap_stats_running = 0;
        global_ctx->shm_export_running = 0;

        /* Signal export thread to stop */
        pthread_mutex_lock(&global_ctx->samples_lock);
        global_ctx->export_running = 0;
        pthread_mutex_unlock(&global_ctx->samples_lock);
        
        /* Signal memory sampling to stop */
        pthread_mutex_lock(&global_ctx->app_memory_metrics->lock);
        global_ctx->mem_sampling_running = 0;
        pthread_mutex_unlock(&global_ctx->app_memory_metrics->lock);

        LOG_INFO("Waiting for sample thread to terminate\n");
        int res = safe_thread_join(global_ctx->mem_sampling_thread, 3);
        if (res != 0)
            LOG_WARN("Sample thread did not terminate cleanly: %d\n", res);

        LOG_INFO("Waiting for export thread to terminate\n");
        res = safe_thread_join(global_ctx->export_thread, 3);
        if (res != 0)
            LOG_WARN("Export thread did not terminate cleanly: %d\n", res);
    
        LOG_INFO("Waiting for heap statistics thread to terminate\n");
        res = safe_thread_join(global_ctx->heap_stats_thread, 3);
        if (res != 0)
            LOG_WARN("Heap statistics thread did not terminate cleanly: %d\n", res);

        if (global_ctx)
        {
            /* Only if we have a valid JNI environment */
            JNIEnv *jni_env = NULL;
            if ((*vm)->GetEnv(vm, (void **)&jni_env, JNI_VERSION_1_6) == JNI_OK && jni_env != NULL) 
            {
                /* Release global reference to Thread class if it exists */
                if (global_ctx->java_thread_class != NULL) 
                {
                    (*jni_env)->DeleteGlobalRef(jni_env, global_ctx->java_thread_class);
                    global_ctx->java_thread_class = NULL;
                }
                /* No need to explicitly free method IDs as they're invalidated when the class is unloaded */
            }
        }

        cleanup(global_ctx);

        /* Clean up all thread-local storage systems */
        cache_tls_cleanup();  /* Clean up cache TLS system */

        /* Free the current thread's TLS data */
        thread_context_t *context = pthread_getspecific(context_key);
        if (context) 
        {
            free(context);
            pthread_setspecific(context_key, NULL);
        }
        
        /* Unfortunately, with pthreads there's no direct way to iterate and free 
        thread-local storage from all threads. It relies on thread exit handlers.
        We can at least delete the key to prevent further allocations. */
        /* Clean up TLS resources */
        pthread_key_delete(context_key);
        
        /* Note: Any other thread that was using TLS will have its destructor called
        when that thread exits. If the JVM creates a lot of threads that don't exit,
        there could still be leaks. This is a limitation of the pthreads API. */
        LOG_WARN("Thread-local storage cleanup may be incomplete for threads that don't exit\n");

        if (global_ctx->app_memory_metrics)
        {
            pthread_mutex_destroy(&global_ctx->app_memory_metrics->lock);
            global_ctx->app_memory_metrics = NULL;
            /* when the arena is destroyed, this memory will be reclaimed */
        }

        /* Cleanup shared memory */
        if (global_ctx->shm_ctx) 
        {   
            int res = safe_thread_join(global_ctx->shm_export_thread, 2);
            if (res != 0)
                LOG_WARN("Shared memory export thread did not terminate cleanly");
            
            cooper_shm_cleanup_agent(global_ctx->shm_ctx);
            global_ctx->shm_ctx = NULL;
        }

        /* Finally shutdown logging */
        cleanup_log_system();

        /* Cleanup the arenas - this will free all cache managers and cache data */
        destroy_all_arenas(global_ctx->arenas, ARENA_ID__LAST);
        /* Null out metrics */
        global_ctx->metrics = NULL;
        global_ctx->object_metrics = NULL;

        /* Destroy mutex */
        pthread_mutex_destroy(&global_ctx->samples_lock);

        free(global_ctx);
        global_ctx = NULL;    
    }
    printf("JVMTI Agent Unloaded.\n");
}
