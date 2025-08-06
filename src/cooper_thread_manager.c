/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper_thread_manager.h"
#include "cooper_thread_workers.h"
#include "cooper.h"
#include "log.h"
#include "thread_util.h"
#include "shared_mem.h"

/*
 * Start all background threads
 * 
 * @param ctx Agent context
 * @return COOPER_OK on success, COOPER_ERR on failure
 */
int start_all_threads(agent_context_t *ctx)
{
    if (!ctx) 
    {
        LOG_ERROR("Cannot start threads with NULL context");
        return COOPER_ERR;
    }
    
    int failed = 0;
    
    /* Start export thread */
    ctx->export_running = 1;
    if (pthread_create(&ctx->export_thread, NULL, export_thread_func, ctx) != 0) {
        LOG_ERROR("Failed to start export thread: %s", strerror(errno));
        ctx->export_running = 0;
        failed++;
    } 
    else
        LOG_INFO("Export thread started");
    
    /* Start memory sampling thread */
    ctx->mem_sampling_running = 1;
    if (pthread_create(&ctx->mem_sampling_thread, NULL, mem_sampling_thread_func, ctx) != 0) {
        LOG_ERROR("Failed to start memory sampling thread: %s", strerror(errno));
        ctx->mem_sampling_running = 0;
        failed++;
    } 
    else
        LOG_INFO("Memory sampling thread started");
    
    /* Start heap statistics thread */
    ctx->heap_stats_running = 1;
    if (pthread_create(&ctx->heap_stats_thread, NULL, heap_stats_thread_func, ctx) != 0) 
    {
        LOG_ERROR("Failed to start heap stats thread: %s", strerror(errno));
        ctx->heap_stats_running = 0;
        failed++;
    } 
    else
        LOG_INFO("Heap statistics thread started");
    
    /* Start shared memory export thread if configured */
    if (ctx->shm_ctx != NULL) 
    {
        /* Initialize shared memory first */
        if (cooper_shm_init_agent(ctx->shm_ctx) != 0) {
            LOG_ERROR("Failed to initialize shared memory for agent");
        } 
        else 
        {
            ctx->shm_export_running = 1;
            if (pthread_create(&ctx->shm_export_thread, NULL, shm_export_thread_func, ctx) != 0) 
            {
                LOG_ERROR("Failed to start shm export thread: %s", strerror(errno));
                ctx->shm_export_running = 0;
                failed++;
            } 
            else
                LOG_INFO("Shared memory export thread started");
        }
    }
    
    if (failed > 0) 
    {
        LOG_WARN("Started threads with %d failures", failed);
        return COOPER_ERR;
    }
    
    LOG_INFO("All background threads started successfully");
    return COOPER_OK;
}

/*
 * Stop all background threads gracefully
 * 
 * @param ctx Agent context
 */
void stop_all_threads(agent_context_t *ctx)
{
    if (!ctx) 
    {
        LOG_ERROR("Cannot stop threads with NULL context");
        return;
    }
    
    LOG_INFO("Stopping all background threads");
    
    /* Signal all threads to stop */
    ctx->export_running = 0;
    ctx->mem_sampling_running = 0;
    ctx->heap_stats_running = 0;
    ctx->shm_export_running = 0;
    
    /* Wait for export thread */
    if (ctx->export_thread) 
    {
        LOG_INFO("Waiting for export thread to terminate");
        int res = safe_thread_join(ctx->export_thread, 3);
        if (res != 0)
            LOG_WARN("Export thread did not terminate cleanly: %d", res);
    }
    
    /* Wait for memory sampling thread */
    if (ctx->mem_sampling_thread) 
    {
        LOG_INFO("Waiting for memory sampling thread to terminate");
        int res = safe_thread_join(ctx->mem_sampling_thread, 3);
        if (res != 0)
            LOG_WARN("Memory sampling thread did not terminate cleanly: %d", res);
    }
    
    /* Wait for heap stats thread */
    if (ctx->heap_stats_thread) 
    {
        LOG_INFO("Waiting for heap statistics thread to terminate");
        int res = safe_thread_join(ctx->heap_stats_thread, 3);
        if (res != 0)
            LOG_WARN("Heap statistics thread did not terminate cleanly: %d", res);
    }
    
    /* Wait for shared memory export thread */
    if (ctx->shm_ctx != NULL && ctx->shm_export_thread) {
        LOG_INFO("Waiting for shared memory export thread to terminate");
        int res = safe_thread_join(ctx->shm_export_thread, 2);
        if (res != 0) {
            LOG_WARN("Shared memory export thread did not terminate cleanly: %d", res);
        }
        
        /* Cleanup shared memory */
        cooper_shm_cleanup_agent(ctx->shm_ctx);
    }
    
    LOG_INFO("All background threads stopped");
}