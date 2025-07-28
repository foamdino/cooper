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
    {EXCEPTION_ARENA_NAME, EXCEPTION_ARENA_SZ, EXCEPTION_ARENA_BLOCKS},
    {LOG_ARENA_NAME, LOG_ARENA_SZ, LOG_ARENA_BLOCKS},
    {SAMPLE_ARENA_NAME, SAMPLE_ARENA_SZ, SAMPLE_ARENA_BLOCKS},
    {CONFIG_ARENA_NAME, CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS},
    {METRICS_ARENA_NAME, METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS},
    {METHOD_CACHE_ARENA_NAME, METHOD_CACHE_ARENA_SZ, METHOD_CACHE_ARENA_BLOCKS},
    {SCRATCH_ARENA_NAME, SCRATCH_ARENA_SZ, SCRATCH_ARENA_BLOCKS},
    {CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS}
    // {HEAP_STATS_ARENA_NAME, HEAP_STATS_ARENA_SZ, HEAP_STATS_ARENA_BLOCKS}
};

//TODO perhaps move these to ctx

/* Cache arena pointers globally to avoid repeated lookups */
static arena_t *cached_method_cache_arena = NULL;
static arena_t *cached_class_cache_arena = NULL;

static const cache_config_t method_cache_config = 
{
    .max_entries = METHOD_CACHE_MAX_ENTRIES,
    .key_size = sizeof(method_cache_key_t),
    .value_size = sizeof(method_cache_value_t),
    .key_compare = method_cache_key_compare,
    .key_copy = NULL,    /* Will use default memcpy */
    .value_copy = NULL,  /* Will use default memcpy */
    .entry_init = NULL,
    .name = METHOD_CACHE_NAME
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
static void init_thread_local_storage() {
    pthread_once(&tls_init_once, init_thread_local_storage_once);
}

/* Get the thread-local sample structure */
static thread_context_t *get_thread_local_context() {

    init_thread_local_storage();
    
    thread_context_t *context = pthread_getspecific(context_key);
    if (!context) {
        /* First time this thread is accessing the key */
        context = calloc(1, sizeof(thread_context_t));
        if (context) {
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
            pthread_mutex_lock(&global_ctx->samples_lock);
            int empty_slot = -1;
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
            {
                LOG_ERROR("No empty slots available for thread mapping");
            } 

            pthread_mutex_unlock(&global_ctx->samples_lock);
        }
        else
        {
            LOG_DEBUG("Cannot get native ID for non-current thread");
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
    sample->parent = NULL;
    
    unsigned int flags = global_ctx->metrics->metric_flags[method_index];

    if (flags & METRIC_FLAG_TIME)
        sample->start_time = get_current_time_ns();
    
    if (flags & METRIC_FLAG_MEMORY)
        sample->current_alloc_bytes = 0;
        
    if (flags & METRIC_FLAG_CPU)
        sample->start_cpu = cycles_start();
    
    return sample;
}

/* Record method execution metrics */
void record_method_execution(agent_context_t *ctx, int method_index, 
    uint64_t exec_time_ns, uint64_t memory_bytes, uint64_t cycles) {

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
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_MEMORY) != 0) 
    {
        metrics->alloc_bytes[method_index] += memory_bytes;
        if (memory_bytes > metrics->peak_memory[method_index])
            metrics->peak_memory[method_index] = memory_bytes;
    }

    /* Update CPU metrics if enabled */
    if ((metrics->metric_flags[method_index] & METRIC_FLAG_CPU) != 0)
        metrics->cpu_cycles[method_index] += cycles;

    pthread_mutex_unlock(&ctx->samples_lock);

    LOG_DEBUG("Method metrics updated: index=%d, samples=%lu, total_time=%lu, alloc=%lu", 
        method_index, 
        (unsigned long)metrics->sample_counts[method_index],
        (unsigned long)metrics->total_time_ns[method_index],
        (unsigned long)metrics->alloc_bytes[method_index]);
}

static object_allocation_metrics_t *init_object_allocation_metrics(arena_t *arena, size_t initial_capacity)
{

    assert(arena != NULL);

    object_allocation_metrics_t *metrics = arena_alloc(arena, sizeof(object_allocation_metrics_t));
    if (!metrics)
        return NULL;

    metrics->capacity = initial_capacity;

    /* Allocate arrays in SoA structure */
    metrics->class_signatures = arena_alloc(arena, initial_capacity * sizeof(char*));
    if (!metrics->class_signatures)
        return NULL;

    metrics->allocation_counts = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->allocation_counts)
        return NULL;

    metrics->total_bytes = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->total_bytes)
        return NULL;

    metrics->peak_instances = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->peak_instances)
        return NULL;

    metrics->current_instances = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->current_instances)
        return NULL;

    metrics->min_size = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->min_size)
        return NULL;

    metrics->max_size = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->max_size)
        return NULL;

    metrics->avg_size = arena_alloc(arena, initial_capacity * sizeof(uint64_t));
    if (!metrics->avg_size)
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

    arena_t *arena = find_arena(global_ctx->arena_head, METRICS_ARENA_NAME);
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
    obj_metrics->allocation_counts[index] = 0;
    obj_metrics->total_bytes[index] = 0;
    obj_metrics->min_size[index] = UINT64_MAX;
    obj_metrics->max_size[index] = 0;
    obj_metrics->current_instances[index] = 0;
    
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

    pthread_mutex_lock(&ctx->samples_lock);
    
    int index = find_or_add_object_type(ctx->object_metrics, class_sig);
    if (index >= 0) 
    {
        ctx->object_metrics->allocation_counts[index]++;
        ctx->object_metrics->total_bytes[index] += safe_sz;
        ctx->object_metrics->current_instances[index]++;
        
        /* Update size statistics */
        if (safe_sz < ctx->object_metrics->min_size[index])
            ctx->object_metrics->min_size[index] = safe_sz;

        if (safe_sz > ctx->object_metrics->max_size[index])
            ctx->object_metrics->max_size[index] = safe_sz;
        
        /* Update average size */
        ctx->object_metrics->avg_size[index] = 
            ctx->object_metrics->total_bytes[index] / ctx->object_metrics->allocation_counts[index];
    }
    
    pthread_mutex_unlock(&ctx->samples_lock);
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
        if (thread_mem > 0) 
        {
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
                arena_t *metrics_arena = find_arena(ctx->arena_head, METRICS_ARENA_NAME);
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

/* Caches class signature in class_info_t using SetTag */
static void cache_class_info(jvmtiEnv *jvmti_env, jclass klass)
{
    char *class_sig = NULL;
    jvmtiError err = (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);
    
    if (err == JVMTI_ERROR_NONE && class_sig != NULL) 
    {
        class_info_t *info = arena_alloc(cached_class_cache_arena, sizeof(class_info_t));
        if (info != NULL) 
        {
            size_t len = strlen(class_sig);
            if (len >= sizeof(info->class_sig)) 
                len = sizeof(info->class_sig) - 1;

            memcpy(info->class_sig, class_sig, len);
            info->class_sig[len] = '\0';
            info->in_heap_iteration = 0;

            jlong tag = (jlong)(intptr_t)info;
            (*jvmti_env)->SetTag(jvmti_env, klass, tag);
        }
        (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_sig);
    }
}

/*
 * Method entry callback
 */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method)
{
    UNUSED(jni);
    UNUSED(thread);
    
    /* Get thread-local context */
    thread_context_t *context = get_thread_local_context();

    if (!context)
        return;

    /* Get our method cache */
    cache_t *cache = cache_tls_get(METHOD_CACHE_NAME, cached_method_cache_arena, &method_cache_config);
    if (!cache) 
        return;

    method_cache_key_t cache_key = { .method_id = method };
    method_cache_value_t cache_value;

    /* Check cache first */
    if (cache_get(cache, &cache_key, &cache_value)) 
    {
        /* Cache hit */
        if (!cache_value.should_sample) 
            return;

        /* Use cached method info for sampling */
        int sample_index = should_sample_method(global_ctx, 
            cache_value.class_signature, cache_value.method_name, cache_value.method_signature);
        
        if (sample_index == 0) 
            return;

        /* Continue with sampling logic using cached values... */
        arena_t *arena = find_arena(global_ctx->arena_head, SAMPLE_ARENA_NAME);
        if (!arena) 
            return;

        method_sample_t *sample = init_method_sample(arena, sample_index - 1, method);
        if (!sample) 
            return;

        sample->parent = context->sample;
        context->sample = sample;
        context->stack_depth++;

        LOG_INFO("[ENTRY] Sampling cached method %s.%s%s\n", 
            cache_value.class_signature, cache_value.method_name, cache_value.method_signature);
        return;
    }

    /* Ok we haven't seen this or it's not cached - miss, get the method info via jvmti */
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaring_class;
    jvmtiError err;

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
 
    //TODO remove this testing/debugging code
    if (strstr(class_signature, "com/github"))
        LOG_DEBUG("Should we sample...: class_sig: (%s) method_name: (%s) method_sig (%s) \n", class_signature, method_name, method_signature);

    /* Check if we should sample this method call */
    int sample_index = should_sample_method(global_ctx, class_signature, method_name, method_signature);

    /* If we get a sample_index of 0 we don't sample this method, so jump to deallocate */
    if (sample_index == 0)
        goto deallocate;
    
    /* Cache the result */
    memset(&cache_value, 0, sizeof(cache_value));
    strncpy(cache_value.class_signature, class_signature, sizeof(cache_value.class_signature) - 1);
    strncpy(cache_value.method_name, method_name, sizeof(cache_value.method_name) - 1);
    strncpy(cache_value.method_signature, method_signature, sizeof(cache_value.method_signature) - 1);
    cache_value.should_sample = (sample_index > 0);

    cache_put(cache, &cache_key, &cache_value);

    /* We're sampling this call */
    LOG_DEBUG("Sampling : %s (%d)\n", method_name, sample_index);

    /* Create a new sample on our method stack */
    arena_t *arena = find_arena(global_ctx->arena_head, SAMPLE_ARENA_NAME);
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

        arena_t *arena = find_arena(global_ctx->arena_head, EXCEPTION_ARENA_NAME);
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

static size_t hash_string(const char *str, size_t capacity)
{
    if (!str || capacity == 0) return 0;
    
    size_t hash = 5381; /* djb2 hash starting prime */
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash % capacity;
}


/* Enhanced find_or_create_stats with additional safety checks */
static class_stats_t *find_or_create_stats(heap_iteration_context_t *ctx, const char *class_sig)
{
    class_hash_table_t *table = ctx->class_table;
    
    /* Enhanced bounds checking */
    if (!table || !table->entries || table->capacity == 0) 
    {
        LOG_ERROR("Invalid hash table state in find_or_create_stats");
        return NULL;
    }
    
    /* Additional validation */
    if (!class_sig || class_sig[0] == '\0')
    {
        LOG_DEBUG("Skipping null or empty class_sig");
        return NULL;
    }
    
    size_t hash = hash_string(class_sig, table->capacity);
    
    /* Linear probing with enhanced bounds checking */
    for (size_t i = 0; i < table->capacity; i++) {
        size_t idx = (hash + i) % table->capacity;
        class_entry_t *entry = &table->entries[idx];
        
        if (!entry->occupied) 
        {
            /* Empty slot - check load factor before creating */
            if (table->count >= table->capacity * 0.75) {
                LOG_ERROR("Hash table load factor exceeded (%zu/%zu)", 
                         table->count, table->capacity);
                return NULL;
            }
            
            /* Create new entry */
            size_t sig_len = strlen(class_sig);
            if (sig_len >= sizeof(entry->class_sig)) 
                sig_len = sizeof(entry->class_sig) - 1;

            memcpy(entry->class_sig, class_sig, sig_len);
            entry->class_sig[sig_len] = '\0';
            
            /* Defensive initialization */
            memset(&entry->stats, 0, sizeof(entry->stats));
            entry->occupied = 1;
            table->count++;
            
            LOG_DEBUG("Created new hash entry for class '%s' at index %zu (load: %zu/%zu)",
                     class_sig, idx, table->count, table->capacity);
            return &entry->stats;
        }
        else if (strcmp(entry->class_sig, class_sig) == 0) 
        {
            /* Found existing entry */
            return &entry->stats;
        }
        /* Continue probing for collisions */
    }
    
    LOG_ERROR("Hash table full, cannot add class signature '%s'", class_sig);
    return NULL; /* Table full */
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
    arena_t *scratch_arena = find_arena(global_ctx->arena_head, SCRATCH_ARENA_NAME);
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
    
    /* Calculate optimal hashtable size with safety checks */
    size_t hash_size = calculate_hashtable_size(class_count);
    
    /* Defensive size calculation with bounds checking */
    size_t hash_table_size = sizeof(class_hash_table_t);
    size_t entries_size;
    
    /* Check for overflow in entries calculation */
    if (hash_size > SIZE_MAX / sizeof(class_entry_t)) {
        LOG_ERROR("Hash table entries size would overflow");
        goto cleanup_classes;
    }
    entries_size = hash_size * sizeof(class_entry_t);
    
    size_t heap_size = TOP_N * sizeof(class_stats_t);
    size_t signature_space = hash_size * 64; /* Average signature length */
    size_t safety_margin = 4096; /* Increased safety margin */
    
    /* Check for total size overflow */
    size_t required_space = hash_table_size + entries_size + heap_size + signature_space + safety_margin;
    if (required_space < hash_table_size) { /* Overflow check */
        LOG_ERROR("Required space calculation overflow");
        goto cleanup_classes;
    }
    
    /* Check available arena space */
    if (scratch_arena->used + required_space > scratch_arena->total_sz) 
    {
        LOG_ERROR("Insufficient arena space: need %zu, have %zu available", 
                  required_space, scratch_arena->total_sz - scratch_arena->used);
        goto cleanup_classes;
    }
    
    LOG_DEBUG("Arena space check passed: using %zu of %zu available bytes", 
              required_space, scratch_arena->total_sz - scratch_arena->used);
    
    /* Safe hashtable allocation */
    class_hash_table_t *table = arena_alloc(scratch_arena, sizeof(class_hash_table_t));
    if (!table) 
    {
        LOG_ERROR("Failed to allocate hash table structure");
        goto cleanup_classes;
    }
    
    table->entries = arena_alloc(scratch_arena, entries_size);
    if (!table->entries) 
    {
        LOG_ERROR("Failed to allocate hash table entries");
        goto cleanup_classes;
    }

    /* table and entries already zero-initialized by arena_alloc */
    table->capacity = hash_size;
    
    LOG_DEBUG("Hash table initialized: capacity=%zu, entry_size=%zu", 
              table->capacity, sizeof(class_entry_t));
    
    /* Create min heap with error checking */
    min_heap_t *heap = min_heap_create(scratch_arena, TOP_N, class_stats_compare);
    if (!heap) 
    {
        LOG_ERROR("Failed to create min heap");
        goto cleanup_classes;
    }
    
    /* Set up iteration context with validation */
    heap_iteration_context_t ctx = {
        .env = env,
        .jvmti = jvmti,
        .arena = scratch_arena,
        .class_table = table,
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
    
    //TODO move this to init_jvm_capabilities instead of setting it each time
    /* Set up heap iteration callbacks */
    jvmtiHeapCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.heap_reference_callback = heap_object_callback;
    
    LOG_INFO("Starting heap iteration (hashtable size: %zu)", hash_size);
    err = (*jvmti)->FollowReferences(jvmti, 0, NULL, NULL, &callbacks, &ctx);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Heap iteration failed: %d", err);
        goto cleanup_tags;
    }
    
    LOG_INFO("Heap iteration completed, processing %zu unique classes", table->count);
    
    /* Process hashtable results into top-N heap with bounds checking */
    size_t processed = 0;
    
    for (size_t i = 0; i < table->capacity && processed < table->count; i++) 
    {
        class_entry_t *entry = &table->entries[i];
        if (entry->stats.instance_count > 0) 
        {
            processed++;
            
            /* Only resolve names for potential top-N entries */
            if (heap->size < TOP_N || 
                entry->stats.total_size > ((class_stats_t*)heap->elements[0])->total_size) 
            {
                class_stats_t *heap_entry = arena_alloc(scratch_arena, sizeof(class_stats_t));
                if (!heap_entry) 
                {
                    LOG_WARN("Failed to allocate heap entry %zu", i);
                    continue;
                }
                
                *heap_entry = entry->stats;
                heap_entry->class_name = arena_strdup(scratch_arena, entry->class_sig);
                /* unable to copy string for some reason */
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
    
    arena_t *config_arena = find_arena(ctx->arena_head, CONFIG_ARENA_NAME);
    if (!config_arena) {
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
    for (size_t i = 0; i < config.num_filters; i++) {
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

    method_metrics_soa_t *metrics = arena_alloc(arena, sizeof(method_metrics_soa_t));
    if (!metrics) return NULL;
    
    metrics->capacity = initial_capacity;
    metrics->count = 0;
    
    /* arena_alloc zeroes memory — no need for manual memset */
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
    arena_t *arena = find_arena(ctx->arena_head, METRICS_ARENA_NAME);
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
    if (method_index < 0) 
    {
        written = snprintf(full_sig, sizeof(full_sig), "%s * *", class_signature);
        if (written >= 0 && written < MAX_SIG_SZ)
            method_index = find_method_index(ctx->metrics, full_sig);
    }
    
    /* If still not found, not a method we want to sample */
    if (method_index < 0)
        return 0;
    
    /* Lock to safely update call count */
    pthread_mutex_lock(&ctx->samples_lock);

    /* We found the method, increment its call count */
    ctx->metrics->call_counts[method_index]++;

    /* Log call count updates for debugging */
    LOG_DEBUG("Method %s call_count incremented to %lu\n", 
        ctx->metrics->signatures[method_index], ctx->metrics->call_counts[method_index]);

    /* Check if we should sample this call based on the sample rate */
    int should_sample = (ctx->metrics->call_counts[method_index] % ctx->metrics->sample_rates[method_index]) == 0;
    LOG_DEBUG("Method %s: call_count=%lu, sample_rate=%d, should_sample=%d\n", 
        ctx->metrics->signatures[method_index], 
        ctx->metrics->call_counts[method_index], 
        ctx->metrics->sample_rates[method_index], 
        should_sample);

    pthread_mutex_unlock(&ctx->samples_lock);

    if (should_sample)
        return method_index + 1;  /* +1 because 0 means "don't sample" */
    
    return 0;  /* Don't sample this call */
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
        return COOPER_ERR;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;
    callbacks.Exception = &exception_callback;
    callbacks.VMObjectAlloc = &object_alloc_callback;
    callbacks.ThreadEnd = &thread_end_callback;
    callbacks.VMInit = &vm_init_callback;
    callbacks.ClassLoad = &class_load_callback;

    err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("SetEventCallbacks failed with error %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_VM_OBJECT_ALLOC, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG_ERROR("Could not enable allocation events: %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_THREAD_END, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Could not enable thread end events: %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Could not enable vm init events: %d\n", err);
        return COOPER_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Could not enable class load: %d\n", err);
        return COOPER_ERR;
    }

    // TODO would be good to set here, but need access in the collect_heap_statistics function
    // /* Set heap callbacks */
    // jvmtiHeapCallbacks heap_callbacks;
    // memset(&callbacks, 0, sizeof(heap_callbacks));
    // heap_callbacks.heap_reference_callback = heap_object_callback;

    return COOPER_OK; /* Success */
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

    /* Cache arena creation before other initializations */
    arena_t *method_cache_arena = find_arena(global_ctx->arena_head, METHOD_CACHE_ARENA_NAME);
    if (!method_cache_arena) 
    {
        LOG_ERROR("Cache arena not found\n");
        return JNI_ERR;
    }

    arena_t *class_cache_arena = find_arena(global_ctx->arena_head, CLASS_CACHE_ARENA_NAME);
    if (!class_cache_arena) 
    {
        LOG_ERROR("Cache arena not found\n");
        return JNI_ERR;
    }

    /* Initialize cache system */
    if (cache_init_system(method_cache_arena) != 0) 
    {
        LOG_ERROR("Failed to initialize cache system\n");
        return JNI_ERR;
    }

    /* Cache the cache arena so it's available globally */
    cached_method_cache_arena = method_cache_arena;
    cached_class_cache_arena = class_cache_arena;

    /* Init logging after all arenas are created */
    arena_t *log_arena = find_arena(global_ctx->arena_head, LOG_ARENA_NAME);
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

    /* Initialize metrics after all arenas are created */
    arena_t *metrics_arena = find_arena(global_ctx->arena_head, METRICS_ARENA_NAME);
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
    arena_t *config_arena = find_arena(global_ctx->arena_head, CONFIG_ARENA_NAME);
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
 * Cleanup state
 * 
 * @param ctx Pointer to an agent_context_t
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
        destroy_all_arenas(&global_ctx->arena_head, &global_ctx->arena_tail);
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
