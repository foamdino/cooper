/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "cooper_thread_workers.h"

/* Helper functions */

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
static pid_t get_native_thread_id(agent_context_t *ctx, JNIEnv *jni, jthread thread)
{
#ifdef __linux__
    pid_t result = 0;
    jvmtiEnv *jvmti_env = ctx->jvmti_env;

    jvmtiPhase jvm_phase;
    if ((*jvmti_env)->GetPhase(jvmti_env, &jvm_phase) != JVMTI_ERROR_NONE || jvm_phase != JVMTI_PHASE_LIVE)
    {
        LOG_DEBUG("Cannot get the thread id as jvm is not in correct phase: %d", jvm_phase);
        return 0;
    }

    if (ctx->java_thread_class == NULL || ctx->getId_method == NULL)
    {
        LOG_ERROR("Failed to get Thread class or getId method");
        return 0;
    }

    /* Get the jvm thread id */
    jlong thread_id = (*jni)->CallLongMethod(jni, thread, ctx->getId_method);
    if ((*jni)->ExceptionCheck(jni)) 
    {
        (*jni)->ExceptionClear(jni);
        LOG_ERROR("Exception occurred while getting thread ID");
        return 0;
    }

    LOG_DEBUG("Looking up Java thread ID: %lld", (long long)thread_id);

    /* Use Thread.getId() as a key to our mapping table */
    pthread_mutex_lock(&ctx->samples_lock);

    /* Check for previous mapping */
    for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
    {
        if (ctx->thread_mappings[i].java_thread_id == thread_id)
        {
            result = ctx->thread_mappings[i].native_thread_id;
            LOG_DEBUG("Found existing mapping: Java ID %lld -> Native ID %d", (long long)thread_id, result);
            pthread_mutex_unlock(&ctx->samples_lock);
            return result;
        }
    }

    pthread_mutex_unlock(&ctx->samples_lock);

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
            pthread_mutex_lock(&ctx->samples_lock);
            for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
            {
                if (ctx->thread_mappings[i].java_thread_id == 0)
                {
                    empty_slot = i;
                    break;
                }
            }

            if (empty_slot >= 0)
            {
                ctx->thread_mappings[empty_slot].java_thread_id = thread_id;
                ctx->thread_mappings[empty_slot].native_thread_id = result;
            } 
            else
                LOG_ERROR("No empty slots available for thread mapping");

            pthread_mutex_unlock(&ctx->samples_lock);
        }
        else
            LOG_DEBUG("Cannot get native ID for non-current thread");
    }

    return result;
#else
    return 0; /* Not implemented for other platforms */
#endif
}

/* thread specific tracking for linux */
static uint64_t get_thread_memory(pid_t native_tid)
{
#ifdef __linux__
    /* Get thread-specific mem info */
    char proc_path[128];
    char buf[4096];

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/statm", getpid(), native_tid);
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
    LOG_DEBUG("Thread %d memory: %llu bytes", native_tid, (unsigned long long)memory_bytes);
    return memory_bytes;
#else
    return 0; /* Not on linux, so 0 */
#endif
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
        pid_t native_tid = get_native_thread_id(ctx, jni, threadObj);
        if (native_tid == 0) 
        {
            LOG_DEBUG("Could not get native thread ID for Java thread %lld", (long long)thread_id);
            goto local_clean;
        }
        
        /* Sample linux thread memory */
        uint64_t thread_mem = get_thread_memory(native_tid);
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

/* Comparison function for class stats (by total_size) */
static int class_stats_compare(const void *a, const void *b) 
{
    const class_stats_t *stats_a = (const class_stats_t*)a;
    const class_stats_t *stats_b = (const class_stats_t*)b;
    
    if (stats_a->total_size < stats_b->total_size) return -1;
    if (stats_a->total_size > stats_b->total_size) return 1;
    return 0;
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
static void collect_heap_statistics(agent_context_t *ctx, JNIEnv *env) 
{
    arena_t *scratch_arena = ctx->arenas[SCRATCH_ARENA_ID];
    if (!scratch_arena) 
    {
        LOG_ERROR("Failed to find scratch arena");
        return;
    }

    /* Reset scratch arena to reclaim previous allocations */
    arena_reset(scratch_arena);

    /* Clear previous heap stats as these are now invalid */
    ctx->last_heap_stats = NULL;
    ctx->last_heap_stats_count = 0;

    // TODO move to config
    const size_t TOP_N = 20;
    
    /* Get loaded classes with error handling */
    int class_count;
    jclass *classes;
    jvmtiEnv *jvmti = ctx->jvmti_env;
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
    heap_iteration_context_t iter_ctx = {
        .env = env,
        .jvmti = jvmti,
        .arena = scratch_arena,
        .class_table = class_ht
    };
    
    /* Validate context before proceeding */
    if (!iter_ctx.env || !iter_ctx.jvmti || !iter_ctx.arena || !iter_ctx.class_table) {
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
    err = (*jvmti)->FollowReferences(jvmti, 0, NULL, NULL, &ctx->callbacks.heap_callbacks, &iter_ctx);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("Heap iteration failed: %d", err);
        goto cleanup_tags;
    }
    
    LOG_INFO("Heap iteration completed, processing %zu unique classes", iter_ctx.class_table->count);
    
    /* Process hashtable results into top-N heap with bounds checking */
    size_t processed = 0;
    
    for (size_t i = 0; i < iter_ctx.class_table->capacity && processed < iter_ctx.class_table->count; i++) 
    {
        ht_entry_t *entry = &iter_ctx.class_table->entries[i];
        
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
    
    ctx->last_heap_stats = heap;
    ctx->last_heap_stats_count = heap->size;
    ctx->last_heap_stats_time = get_current_time_ns();
    LOG_DEBUG("Stored heap statistics: %zu classes at time %llu", 
                heap->size, (unsigned long long)ctx->last_heap_stats_time);

    
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

/* Thread functions */

void *export_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;

    LOG_INFO("Export thread started, interval=%d seconds\n", ctx->config.export_interval);
    
    /* Initial export to create the file */
    export_to_file(ctx);

    /* export to file while export_running flag is set */
    while (__atomic_load_n(&ctx->export_running, __ATOMIC_ACQUIRE)) 
    {
        LOG_DEBUG("Export thread sleeping for %d seconds\n", ctx->config.export_interval);
        /* Sleep in smaller increments to be more responsive to shutdown */
        for (int i = 0; i < ctx->config.export_interval && __atomic_load_n(&ctx->export_running, __ATOMIC_ACQUIRE); i++)
            sleep(1);
        
        if (__atomic_load_n(&ctx->export_running, __ATOMIC_ACQUIRE)) 
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
 * Shared memory export thread function
 */
void *shm_export_thread_func(void *arg) {
    agent_context_t *ctx = (agent_context_t *)arg;
    
    LOG_INFO("Shared memory export thread started");
    
    /* TODO move export interval to const */
    while (ctx->export_running) {
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
        collect_heap_statistics(ctx, jni);
        
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