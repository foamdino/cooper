/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper_thread_manager.h"
#include "cooper_thread_workers.h"

/*
 * Start all background threads
 *
 * @param ctx Agent context
 * @return COOPER_OK on success, COOPER_ERR on failure
 */
int
start_all_threads(agent_context_t *ctx)
{
	if (!ctx)
	{
		LOG_ERROR("Cannot start threads with NULL context");
		return COOPER_ERR;
	}

	/* Start export thread */
	set_worker_status(&ctx->tm_ctx.worker_statuses, EXPORT_RUNNING);
	if (pthread_create(&ctx->tm_ctx.export_thread, NULL, export_thread_func, ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start export thread: %s", strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses, EXPORT_RUNNING);
		return COOPER_ERR;
	}
	else
		LOG_INFO("Export thread started");

	/* Start memory sampling thread */
	set_worker_status(&ctx->tm_ctx.worker_statuses, MEM_SAMPLING_RUNNING);
	if (pthread_create(
		&ctx->tm_ctx.mem_sampling_thread, NULL, mem_sampling_thread_func, ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start memory sampling thread: %s", strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses, MEM_SAMPLING_RUNNING);
		return COOPER_ERR;
	}
	else
		LOG_INFO("Memory sampling thread started");

	/* Start heap statistics thread */
	set_worker_status(&ctx->tm_ctx.worker_statuses, HEAP_STATS_RUNNING);
	if (pthread_create(
		&ctx->tm_ctx.heap_stats_thread, NULL, heap_stats_thread_func, ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start heap stats thread: %s", strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses, HEAP_STATS_RUNNING);
		return COOPER_ERR;
	}
	else
		LOG_INFO("Heap statistics thread started");

	/* Start shared memory export thread if configured */
	if (ctx->shm_ctx != NULL)
	{
		/* Initialize shared memory first */
		if (cooper_shm_init_agent(ctx->shm_ctx) != 0)
		{
			LOG_ERROR("Failed to initialize shared memory for agent");
		}
		else
		{
			set_worker_status(&ctx->tm_ctx.worker_statuses,
			                  SHM_EXPORT_RUNNING);
			if (pthread_create(&ctx->tm_ctx.shm_export_thread,
			                   NULL,
			                   shm_export_thread_func,
			                   ctx)
			    != 0)
			{
				LOG_ERROR("Failed to start shm export thread: %s",
				          strerror(errno));
				clear_worker_status(&ctx->tm_ctx.worker_statuses,
				                    SHM_EXPORT_RUNNING);
				return COOPER_ERR;
			}
			else
				LOG_INFO("Shared memory export thread started");
		}
	}

	/* Start class caching background thread */
	set_worker_status(&ctx->tm_ctx.worker_statuses, CLASS_CACHE_RUNNING);
	ctx->class_queue->running = 1;
	if (pthread_create(
		&ctx->tm_ctx.class_cache_thread, NULL, class_cache_thread_func, ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start class caching thread: %s", strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses, CLASS_CACHE_RUNNING);
		ctx->class_queue->running = 0;
		return COOPER_ERR;
	}
	else
		LOG_INFO("Class caching thread started");

	/* Start background call stack sampling thread */
	set_worker_status(&ctx->tm_ctx.worker_statuses, CALL_STACK_RUNNNG);
	if (pthread_create(&ctx->tm_ctx.call_stack_sample_thread,
	                   NULL,
	                   call_stack_sampling_thread_func,
	                   ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start call stack sampling thread: %s",
		          strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses, CALL_STACK_RUNNNG);
		return COOPER_ERR;
	}
	else
		LOG_INFO("Call stack sampling thread started");

	/* Start flamegraph / call stack export */
	set_worker_status(&ctx->tm_ctx.worker_statuses, FLAMEGRAPH_EXPORT_RUNNING);
	if (pthread_create(&ctx->tm_ctx.flamegraph_export_thread,
	                   NULL,
	                   flamegraph_export_thread,
	                   ctx)
	    != 0)
	{
		LOG_ERROR("Failed to start flamegraph export thread: %s",
		          strerror(errno));
		clear_worker_status(&ctx->tm_ctx.worker_statuses,
		                    FLAMEGRAPH_EXPORT_RUNNING);
		return COOPER_ERR;
	}
	else
		LOG_INFO("Flamegraph export thread started");

	LOG_INFO("All background threads started successfully");
	return COOPER_OK;
}

/*
 * Stop all background threads gracefully
 *
 * @param ctx Agent context
 */
void
stop_all_threads(agent_context_t *ctx)
{
	if (!ctx)
	{
		LOG_ERROR("Cannot stop threads with NULL context");
		return;
	}

	LOG_INFO("Stopping all background threads");

	/* Signal all threads to stop */
	/* Zero all flag/bits */
	ctx->tm_ctx.worker_statuses = 0;

	LOG_INFO("Stopping call stack sampling thread");
	if (ctx->tm_ctx.call_stack_sample_thread)
	{
		LOG_INFO("Waiting for call stack sampling thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.call_stack_sample_thread, 3);
		if (res != 0)
			LOG_WARN(
			    "Call stack sampling thread did not terminate cleanly: %d",
			    res);
	}

	/* Wait for export thread */
	if (ctx->tm_ctx.export_thread)
	{
		LOG_INFO("Waiting for export thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.export_thread, 3);
		if (res != 0)
			LOG_WARN("Export thread did not terminate cleanly: %d", res);
	}

	/* Wait for memory sampling thread */
	if (ctx->tm_ctx.mem_sampling_thread)
	{
		LOG_INFO("Waiting for memory sampling thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.mem_sampling_thread, 3);
		if (res != 0)
			LOG_WARN("Memory sampling thread did not terminate cleanly: %d",
			         res);
	}

	/* Wait for heap stats thread */
	if (ctx->tm_ctx.heap_stats_thread)
	{
		LOG_INFO("Waiting for heap statistics thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.heap_stats_thread, 3);
		if (res != 0)
			LOG_WARN("Heap statistics thread did not terminate cleanly: %d",
			         res);
	}

	/* Wait for shared memory export thread */
	if (ctx->shm_ctx != NULL && ctx->tm_ctx.shm_export_thread)
	{
		LOG_INFO("Waiting for shared memory export thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.shm_export_thread, 2);
		if (res != 0)
		{
			LOG_WARN(
			    "Shared memory export thread did not terminate cleanly: %d",
			    res);
		}

		/* Cleanup shared memory */
		cooper_shm_cleanup_agent(ctx->shm_ctx);
	}

	if (ctx->tm_ctx.class_cache_thread)
	{
		if (ctx->class_queue)
		{
			/* Signal the queue to shutdown */
			pthread_mutex_lock(&ctx->class_queue->lock);
			ctx->class_queue->running = 0;
			pthread_cond_broadcast(
			    &ctx->class_queue->cond); /* Wake up waiting thread */
			pthread_mutex_unlock(&ctx->class_queue->lock);
		}
		LOG_INFO("Waiting for class caching thread to terminate");
		int res = safe_thread_join(ctx->tm_ctx.class_cache_thread, 3);
		if (res != 0)
			LOG_WARN("Class caching thread did not terminate cleanly: %d",
			         res);
	}
}