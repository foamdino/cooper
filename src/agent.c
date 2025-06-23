/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


//TODO tidy these:

#include "cooper.h"

#include "agent.h"

static int init_jvm_capabilities(agent_context_t *ctx)
{
    assert(ctx != NULL);

    if (!ctx) return COOPER_ERR;

    jvmtiCapabilities capabilities;
    // jvmtiEventCallbacks callbacks;
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

    err = (*ctx->jvmti_env)->AddCapabilities(ctx->jvmti_env, &capabilities);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG_ERROR("AddCapabilities failed with error %d\n", err);
        return COOPER_ERR;
    }

    // /* Set callbacks */
    // memset(&callbacks, 0, sizeof(callbacks));
    // callbacks.MethodEntry = &method_entry_callback;
    // callbacks.MethodExit = &method_exit_callback;
    // callbacks.Exception = &exception_callback;
    // callbacks.VMObjectAlloc = &object_alloc_callback;
    // callbacks.ThreadEnd = &thread_end_callback;
    // callbacks.VMInit = &vm_init_callback;

    // err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &callbacks, sizeof(callbacks));
    // if (err != JVMTI_ERROR_NONE) 
    // {
    //     LOG_ERROR("SetEventCallbacks failed with error %d\n", err);
    //     return COOPER_ERR;
    // }

    // /* Enable event notifications */
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    // if (err != JVMTI_ERROR_NONE) 
    // {
    //     LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    // if (err != JVMTI_ERROR_NONE)
    // {
    //     LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, NULL);
    // if (err != JVMTI_ERROR_NONE)
    // {
    //     LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, NULL);
    // if (err != JVMTI_ERROR_NONE)
    // {
    //     LOG_ERROR("SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_VM_OBJECT_ALLOC, NULL);
    // if (err != JVMTI_ERROR_NONE)
    // {
    //     LOG_ERROR("Could not enable allocation events: %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_THREAD_END, NULL);
    // if (err != JVMTI_ERROR_NONE) 
    // {
    //     LOG_ERROR("Could not enable thread end events: %d\n", err);
    //     return COOPER_ERR;
    // }
    // err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL);
    // if (err != JVMTI_ERROR_NONE) 
    // {
    //     LOG_ERROR("Could not enable vm init events: %d\n", err);
    //     return COOPER_ERR;
    // }

    return COOPER_OK; /* Success */
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    UNUSED(reserved);

    agent_context_t *ctx = init_cooper(options);
    if (!ctx)
        return JNI_ERR;

    /* At this point the arenas are allocated and logging system should be running */

    /* Grab a copy of the JVM pointer */
    ctx->jvm = vm;

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&ctx->jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || ctx->jvmti_env == NULL) 
    {
        LOG_ERROR("Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    if (init_jvm_capabilities(ctx) != COOPER_OK)
        return JNI_ERR;

    // TODO temp call cooper to set callbacks

    if (cooper_set_callbacks(ctx) != COOPER_OK)
        return JNI_ERR;
    
    // /* Allocate and initialize the agent context */
    // global_ctx = malloc(sizeof(agent_context_t));
    // if (!global_ctx) 
    // {
    //     printf("Failed to allocate agent context\n");
    //     return JNI_ERR;
    // }
    // memset(global_ctx, 0, sizeof(agent_context_t));
    // global_ctx->jvmti_env = NULL;
    // global_ctx->jvm = NULL;
    // global_ctx->java_thread_class = NULL;
    // global_ctx->getId_method = NULL;
    // global_ctx->method_filters = NULL;
    // global_ctx->num_filters = 0;
    // global_ctx->log_file = NULL;
    // global_ctx->config.rate = 1;
    // global_ctx->config.filters = NULL;
    // global_ctx->config.num_filters = 0;
    // global_ctx->config.sample_file_path = NULL;
    // global_ctx->config.export_method = NULL;
    // global_ctx->config.export_interval = 60;
    // global_ctx->config.mem_sample_interval = 1;
    // global_ctx->metrics = NULL;
    // global_ctx->object_metrics = NULL;
    // global_ctx->arena_head = NULL;
    // global_ctx->arena_tail = NULL;
    // global_ctx->thread_mem_head = NULL;
    // global_ctx->shm_ctx = NULL;
    // pthread_mutex_init(&global_ctx->samples_lock, NULL);
    // memset(global_ctx->thread_mappings, 0, sizeof(global_ctx->thread_mappings));

    // /* Redirect output */
    // if (options && strncmp(options, "logfile=", 8) == 0)
    // {
    //     global_ctx->log_file = fopen(options + 8, "w");
    //     if (!global_ctx->log_file)
    //     {
    //         printf("Failed to open log file: %s, reverting to stdout\n", options + 8);
    //         global_ctx->log_file = stdout;
    //     }
    // }

    // if (options && strstr(options, "loglevel=debug"))
    //     current_log_level = LOG_LEVEL_DEBUG;

    // log_q_t *log_queue = malloc(sizeof(log_q_t));

    // /* 
    //   We initialise all the arenas we need in this function and we
    //   destroy all the arenas in the corresponding Agent_OnUnload
    // */

    // /* Number of arena configurations in the table */
    // const size_t num_arenas = sizeof(arena_configs) / sizeof(arena_configs[0]);
    // /* Create each arena from the configuration table */
    // for (size_t i = 0; i < num_arenas; i++) {
    //     arena_t *arena = create_arena(
    //         &global_ctx->arena_head, 
    //         &global_ctx->arena_tail, 
    //         arena_configs[i].name, 
    //         arena_configs[i].size, 
    //         arena_configs[i].block_count
    //     );
        
    //     if (!arena) 
    //     {
    //         printf("Failed to create %s\n", arena_configs[i].name);
    //         return JNI_ERR;
    //     }
    // }

    // /* Cache arena creation before other initializations */
    // arena_t *cache_arena = find_arena(global_ctx->arena_head, CACHE_ARENA_NAME);
    // if (!cache_arena) 
    // {
    //     LOG_ERROR("Cache arena not found\n");
    //     return JNI_ERR;
    // }

    // /* Initialize cache system */
    // if (cache_init_system(cache_arena) != 0) 
    // {
    //     LOG_ERROR("Failed to initialize cache system\n");
    //     return JNI_ERR;
    // }

    // /* Init logging after all arenas are created */
    // arena_t *log_arena = find_arena(global_ctx->arena_head, LOG_ARENA_NAME);
    // if (!log_arena) 
    // {
    //     printf("Log arena not found\n");
    //     return JNI_ERR;
    // }

    // /* We start the logging thread as we initialise the system now */
    // if (init_log_system(log_queue, log_arena, global_ctx->log_file) != COOPER_OK)
    // {
    //     cleanup(global_ctx);
    //     return JNI_ERR;
    // }

    // /* Initialize metrics after all arenas are created */
    // arena_t *metrics_arena = find_arena(global_ctx->arena_head, METRICS_ARENA_NAME);
    // if (!metrics_arena) 
    // {
    //     LOG_ERROR("Metrics arena not found\n");
    //     return JNI_ERR;
    // }

    // /* TODO create const for initial_capacity at some point */
    // size_t initial_capacity = 256;
    // global_ctx->metrics = init_method_metrics(metrics_arena, initial_capacity);
    // if (!global_ctx->metrics) 
    // {
    //     LOG_ERROR("Failed to initialize metrics structure\n");
    //     return JNI_ERR;
    // }

    // LOG_DEBUG("Metrics arena usage before object init: %zu / %zu bytes\n", metrics_arena->used, metrics_arena->total_sz);

    // /* Add object allocation metrics initialization */
    // global_ctx->object_metrics = init_object_allocation_metrics(metrics_arena, MAX_OBJECT_TYPES);
    // if (!global_ctx->object_metrics) 
    // {
    //     LOG_ERROR("Failed to initialize object allocation metrics structure\n");
    //     return JNI_ERR;
    // }

    // LOG_DEBUG("Metrics arena usage after object init: %zu / %zu bytes\n", metrics_arena->used, metrics_arena->total_sz);

    // global_ctx->app_memory_metrics = arena_alloc(metrics_arena, sizeof(app_memory_metrics_t));
    // if (!global_ctx->app_memory_metrics)
    // {
    //     LOG_ERROR("Failed to allocate memory for app_memory_metrics\n");
    //     return JNI_ERR;
    // }
    // memset(global_ctx->app_memory_metrics, 0, sizeof(app_memory_metrics_t));
    // pthread_mutex_init(&global_ctx->app_memory_metrics->lock, NULL);
    
    // /* Initialize shared memory */
    // global_ctx->shm_ctx = malloc(sizeof(cooper_shm_context_t));
    // if (!global_ctx->shm_ctx) 
    // {
    //     LOG_ERROR("Failed to allocate shared memory context");
    //     return JNI_ERR;
    // }

    // /* Grab a copy of the JVM pointer */
    // global_ctx->jvm = vm;

    // /* Get JVMTI environment */
    // jint result = (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
    // if (result != JNI_OK || global_ctx->jvmti_env == NULL) 
    // {
    //     LOG_ERROR("Unable to access JVMTI!\n");
    //     return JNI_ERR;
    // }

    // /* Now we have logging configured, load config */
    // if (load_config(global_ctx, "./trace.ini") != COOPER_OK)
    // {
    //     LOG_ERROR("Unable to load config_file!\n");
    //     return JNI_ERR;
    // }

    // LOG_INFO("Config: rate=%d, method='%s', path='%s'\n",
    //     global_ctx->config.rate, global_ctx->config.export_method, global_ctx->config.sample_file_path);

    // if (strcmp(global_ctx->config.export_method, "file") != 0)
    // {
    //     LOG_ERROR("Unknown export method: [%s]", global_ctx->config.export_method);
    //     return JNI_ERR;
    // }

    // /* Set export_running to true before starting the thread */
    // global_ctx->export_running = 1;

    // /* Init the event/sample handling */
    // if (start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != 0)
    // {
    //     cleanup(global_ctx);
    //     cleanup_log_system();
    //     return JNI_ERR;
    // }

    // if (cooper_shm_init_agent(global_ctx->shm_ctx) != 0) 
    // {
    //     LOG_WARN("Failed to initialize shared memory - continuing without it");
    //     free(global_ctx->shm_ctx);
    //     global_ctx->shm_ctx = NULL;
    // } 
    // else 
    // {
    //     /* Start shared memory export thread */
    //     global_ctx->shm_export_running = 1;
    //     if (start_thread(&global_ctx->shm_export_thread, &shm_export_thread_func, "shm-export", global_ctx) != 0) 
    //     {
    //         LOG_INFO("Failed to start shared memory export thread");
    //         cooper_shm_cleanup_agent(global_ctx->shm_ctx);
    //         free(global_ctx->shm_ctx);
    //         global_ctx->shm_ctx = NULL;
    //         global_ctx->shm_export_running = 0;
    //     } else {
    //         LOG_INFO("Shared memory export enabled");
    //     }
    // }

    LOG_INFO("JVMTI Agent Loaded.\n");
    return JNI_OK;
}