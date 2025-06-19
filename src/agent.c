/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "agent.h"

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    UNUSED(reserved);
    
    /* Allocate and initialize the agent context */
    global_ctx = malloc(sizeof(agent_context_t));
    if (!global_ctx) 
    {
        printf("Failed to allocate agent context\n");
        return JNI_ERR;
    }
    memset(global_ctx, 0, sizeof(agent_context_t));
    global_ctx->jvmti_env = NULL;
    global_ctx->jvm = NULL;
    global_ctx->java_thread_class = NULL;
    global_ctx->getId_method = NULL;
    global_ctx->method_filters = NULL;
    global_ctx->num_filters = 0;
    global_ctx->log_file = NULL;
    global_ctx->config.rate = 1;
    global_ctx->config.filters = NULL;
    global_ctx->config.num_filters = 0;
    global_ctx->config.sample_file_path = NULL;
    global_ctx->config.export_method = NULL;
    global_ctx->config.export_interval = 60;
    global_ctx->config.mem_sample_interval = 1;
    global_ctx->metrics = NULL;
    global_ctx->object_metrics = NULL;
    global_ctx->arena_head = NULL;
    global_ctx->arena_tail = NULL;
    global_ctx->thread_mem_head = NULL;
    global_ctx->shm_ctx = NULL;
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
    arena_t *cache_arena = find_arena(global_ctx->arena_head, CACHE_ARENA_NAME);
    if (!cache_arena) 
    {
        LOG_ERROR("Cache arena not found\n");
        return JNI_ERR;
    }

    /* Initialize cache system */
    if (cache_init_system(cache_arena) != 0) 
    {
        LOG_ERROR("Failed to initialize cache system\n");
        return JNI_ERR;
    }

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
    memset(global_ctx->app_memory_metrics, 0, sizeof(app_memory_metrics_t));
    pthread_mutex_init(&global_ctx->app_memory_metrics->lock, NULL);
    
    /* Initialize shared memory */
    global_ctx->shm_ctx = malloc(sizeof(cooper_shm_context_t));
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

    /* Set export_running to true before starting the thread */
    global_ctx->export_running = 1;

    /* Init the event/sample handling */
    if (start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != COOPER_OK)
    {
        cleanup(global_ctx);
        cleanup_log_system();
        return JNI_ERR;
    }

    if (cooper_shm_init_agent(global_ctx->shm_ctx) != 0) 
    {
        LOG_WARN("Failed to initialize shared memory - continuing without it");
        free(global_ctx->shm_ctx);
        global_ctx->shm_ctx = NULL;
    } 
    else 
    {
        /* Start shared memory export thread */
        global_ctx->shm_export_running = 1;
        if (start_thread(&global_ctx->shm_export_thread, &shm_export_thread_func, "shm-export", global_ctx) != COOPER_OK) 
        {
            LOG_INFO("Failed to start shared memory export thread");
            cooper_shm_cleanup_agent(global_ctx->shm_ctx);
            free(global_ctx->shm_ctx);
            global_ctx->shm_ctx = NULL;
            global_ctx->shm_export_running = 0;
        } 
        else 
            LOG_INFO("Shared memory export enabled");
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

        if (global_ctx->app_memory_metrics)
        {
            pthread_mutex_destroy(&global_ctx->app_memory_metrics->lock);
            global_ctx->app_memory_metrics = NULL;
            /* when the arena is destroyed, this memory will be reclaimed */
        }

        /* Cleanup shared memory */
        if (global_ctx->shm_ctx) 
        {
            global_ctx->shm_export_running = 0;
            
            int res = safe_thread_join(global_ctx->shm_export_thread, 2);
            if (res != 0)
                LOG_WARN("Shared memory export thread did not terminate cleanly");
            
            cooper_shm_cleanup_agent(global_ctx->shm_ctx);
            free(global_ctx->shm_ctx);
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
