/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper_threads.h"
#include "src/agent/cooper.h"
#include "src/agent/cooper_types.h"
#include "src/lib/arena.h"
#include "src/lib/arena_str.h"
#include "src/lib/log.h"
#include "src/lib/ring/mpsc_ring.h"
#include "src/lib/thread_util.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* clang-format off */
static const thread_cfg_t thread_cfgs[] = 
{
    {"Export", THREAD_ID_EXPORT, export_thread_func, EXPORT_RUNNING},
	{"Memory sampling", THREAD_ID_MEM_SAMPLING, mem_sampling_thread_func, MEM_SAMPLING_RUNNING},
	{"Heap stats", THREAD_ID_HEAP_STATS, heap_stats_thread_func, HEAP_STATS_RUNNING},
	{"SHM export", THREAD_ID_SHM_EXPORT, shm_export_thread_func, SHM_EXPORT_RUNNING},
	{"Class caching", THREAD_ID_CLASS_CACHE, class_cache_thread_func, CLASS_CACHE_RUNNING},
	{"Call stack sampling", THREAD_ID_CALL_STACK, call_stack_sampling_thread_func, CALL_STACK_RUNNING},
	{"Flamegraph export", THREAD_ID_FLAMEGRAPH, flamegraph_export_thread, FLAMEGRAPH_EXPORT_RUNNING},
	{"Method events", THREAD_ID_METHOD_EVENTS, method_event_thread_func, METHOD_EVENTS_RUNNING},
	{"Object alloc events", THREAD_ID_OBJ_ALLOC, obj_alloc_event_thread_func, OBJ_ALLOC_EVENTS_RUNNING}
};

/* Lookups for deep size estimates */
static const deep_sz_cfg_t deep_sz_cfgs[] =
{
	/* Core library and framework classes */
	{"java/lang/String", 2, 0},
	{"java/lang/", 2, 0},
	{"java/time/", 2, 0},
	{"java/util/HashMap", 4, 0},
	{"java/util/ConcurrentHashMap", 4, 0},
	{"java/util/ArrayList", 3, 0},
	{"java/util/", 3, 0},
	{"org/springframework/data/", 3, 64 * 1024},
	{"org/hibernate/", 3, 64 * 1024},
	{"javax/persistence/", 3, 64 * 1024},
	{"org/springframework/", 2, 8 * 1024},

	/* Typical classes in a Java microservice */
	{"Repository", 3, 64 * 1024},
	{"DAO", 3, 64 * 1024},
	{"Controller", 2, 8 * 1024},
	{"Resource", 2, 8 * 1024},
	{"Transformer", 2, 8 * 1024},
	{"Mapper", 2, 8 * 1024},
	{"Service", 2, 8 * 1024},
	{"Consumer", 2, 8 * 1024},
	{"Producer", 2, 8 * 1024},
};
/* clang-format on */

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

	for (size_t i = 0; i < THREAD_ID__COUNT; i++)
	{
		const thread_cfg_t *cfg = &thread_cfgs[i];

		set_worker_status(&ctx->tm_ctx.worker_statuses, cfg->status);

		if (pthread_create(
			&ctx->tm_ctx.threads[cfg->id], NULL, cfg->thread_fn, ctx)
		    != 0)
		{
			LOG_ERROR(
			    "Failed to start %s thread: %s", cfg->name, strerror(errno));
			clear_worker_status(&ctx->tm_ctx.worker_statuses, cfg->status);
			return COOPER_ERR;
		}
		else
			LOG_INFO("%s thread started", cfg->name);
	}

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

	if (ctx->tm_ctx.worker_statuses == 0)
	{
		LOG_DEBUG(
		    "stop_all_threads called but threads already signalled to stop");
		return;
	}

	LOG_INFO("Stopping all background threads");

	/* Signal all threads to stop */
	/* Zero all flag/bits */
	ctx->tm_ctx.worker_statuses = 0;

	for (size_t i = 0; i < THREAD_ID__COUNT; i++)
	{
		const thread_cfg_t *cfg = &thread_cfgs[i];

		LOG_INFO("Waiting for %s thread to terminate", cfg->name);
		int res = safe_thread_join(ctx->tm_ctx.threads[cfg->id], 2);
		if (res != 0)
			LOG_WARN("%s did not terminate "
			         "cleanly: %d",
			         cfg->name,
			         res);
	}
}

/* Helper functions */

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
static pid_t
get_native_thread_id(agent_context_t *ctx, JNIEnv *jni, jthread thread)
{
#ifdef __linux__
	pid_t result        = 0;
	jvmtiEnv *jvmti_env = ctx->jvmti_env;

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

	/* Use Thread.getId() as a key to our mapping table */
	pthread_mutex_lock(&ctx->tm_ctx.samples_lock);

	/* Check for previous mapping */
	for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
	{
		if (ctx->thread_mappings[i].java_thread_id == thread_id)
		{
			result = ctx->thread_mappings[i].native_thread_id;
			LOG_DEBUG("Found existing mapping: Java ID %lld -> Native ID %d",
			          (long long)thread_id,
			          result);
			pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);
			return result;
		}
	}

	pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);

	/*
	This is a new thread id, not previously found in our mappings.
	We'll need to have the thread tell us its native ID. This part
	can only be done from within the thread itself...
	*/

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
		LOG_DEBUG("Current thread ID: %d for Java thread ID: %lld",
		          result,
		          (long long)thread_id);

		/* Add to our map */
		int empty_slot = -1;
		pthread_mutex_lock(&ctx->tm_ctx.samples_lock);
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
			ctx->thread_mappings[empty_slot].java_thread_id   = thread_id;
			ctx->thread_mappings[empty_slot].native_thread_id = result;
		}
		else
			LOG_ERROR("No empty slots available for thread mapping");

		pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);
	}

	return result;
#else
	return 0; /* Not implemented for other platforms */
#endif
}

/**
 *
 *@param ctx Pointer to agent_context_t
 */
void
export_to_file(agent_context_t *ctx)
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
		LOG_ERROR("Failed to open sample file: %s\n",
		          ctx->config.sample_file_path);
		return;
	}

	/* Write header with time stamp */
	time_t now;
	time(&now);

	/* Export application memory samples */
	fprintf(fp, "# Application Memory Metrics\n");
	fprintf(fp, "# Format: timestamp, process_memory_bytes\n");

	/* Lock app memory metrics for thread-safe access */
	pthread_mutex_lock(&ctx->app_memory_metrics->lock);

	/* Export memory samples in chronological order */
	size_t mem_sample_total = ctx->app_memory_metrics->sample_count;
	size_t export_count =
	    mem_sample_total < MAX_MEMORY_SAMPLES ? mem_sample_total : MAX_MEMORY_SAMPLES;
	for (size_t i = 0; i < export_count; i++)
	{
		size_t idx;
		if (mem_sample_total <= MAX_MEMORY_SAMPLES)
			idx = i; /* buffer not full so we can use i */
		else
		{
			/* buffer is full, start from the oldest entry */
			size_t oldest_idx = mem_sample_total % MAX_MEMORY_SAMPLES;
			idx               = (oldest_idx + i) % MAX_MEMORY_SAMPLES;
		}

		fprintf(fp,
		        "%" PRIu64 ",%" PRIu64 "\n",
		        ctx->app_memory_metrics->timestamps[idx],
		        ctx->app_memory_metrics->process_memory_sample[idx]);
	}

	fprintf(fp, "# ------ \n\n");

	/* Export thread memory metrics next */
	fprintf(fp, "# Thread Memory Metrics\n");
	fprintf(fp, "# Format: thread_id, timestamp, thread_memory_bytes\n");

	/* Find the head of the thread metrics linked list (should be stored in global
	 * context) */
	thread_memory_metrics_t *thread_metrics = ctx->thread_mem_head;
	int thread_count                        = 0;

	/* Iterate through the thread metrics linked list */
	while (thread_metrics)
	{
		thread_count++;
		fprintf(fp, "# Thread ID: %lld\n", (long long)thread_metrics->thread_id);

		for (size_t i = 0;
		     i < thread_metrics->sample_count && i < MAX_MEMORY_SAMPLES;
		     i++)
		{
			size_t idx;
			if (thread_metrics->sample_count <= MAX_MEMORY_SAMPLES)
				idx = i; /* buffer not full yet so just set idx */
			else
			{
				/* buffer is full we need to start from the oldest entry,
				this would be the position of the next entry to be written
				*/
				size_t oldest_idx =
				    thread_metrics->sample_count % MAX_MEMORY_SAMPLES;
				/* add current pos and wrap around if required */
				idx = (oldest_idx + i) % MAX_MEMORY_SAMPLES;
			}

			fprintf(fp,
			        "%" PRId64 ",%" PRIu64 ",%" PRIu64 "\n",
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
		fprintf(fp,
		        "# Format: class_signature, allocation_count, total_bytes, "
		        "current_instances, avg_size, min_size, max_size\n");

		for (size_t i = 0; i < obj_metrics->count; i++)
		{
			uint64_t alloc_count  = obj_metrics->allocation_counts[i];
			uint64_t total_bytes  = obj_metrics->total_bytes[i];
			uint64_t current_inst = obj_metrics->current_instances[i];
			uint64_t min_size     = obj_metrics->min_size[i];
			uint64_t max_size     = obj_metrics->max_size[i];
			uint64_t avg_size =
			    (alloc_count > 0) ? total_bytes / alloc_count : 0;

			fprintf(fp,
			        "%s,%lu,%lu,%lu,%lu,%lu,%lu\n",
			        obj_metrics->class_signatures[i],
			        (unsigned long)alloc_count,
			        (unsigned long)total_bytes,
			        (unsigned long)current_inst,
			        (unsigned long)avg_size,
			        (unsigned long)min_size,
			        (unsigned long)max_size);
		}
	}
	else
		fprintf(fp, "# No object allocation metrics available\n");

	fprintf(fp, "# ------ \n\n");

	fprintf(fp, "# Method Metrics Export - %s", ctime(&now));
	fprintf(
	    fp,
	    "# Format: signature, call_count, sample_count, total_time_ns, avg_time_ns, "
	    "min_time_ns, max_time_ns, alloc_bytes, peak_memory, cpu_cycles\n");

	/* Debug output to verify data being exported */
	LOG_INFO("Exporting %zu method metrics\n", ctx->metrics->count);

	/* Export the entire method_metrics_soa structure */
	size_t total_calls   = 0;
	size_t total_samples = 0;
	for (size_t i = 0; i < ctx->metrics->count; i++)
	{
		if (ctx->metrics->signatures[i])
		{
			/* Calculate avg time if samples exist */
			uint64_t avg_time = 0;

			uint64_t call_count = atomic_load_explicit(
			    &ctx->metrics->call_counts[i], memory_order_relaxed);
			uint64_t total_time = atomic_load_explicit(
			    &ctx->metrics->total_time_ns[i], memory_order_relaxed);
			uint64_t min_time = atomic_load_explicit(
			    &ctx->metrics->min_time_ns[i], memory_order_relaxed);
			uint64_t max_time = atomic_load_explicit(
			    &ctx->metrics->max_time_ns[i], memory_order_relaxed);
			uint64_t alloc = atomic_load_explicit(
			    &ctx->metrics->alloc_bytes[i], memory_order_relaxed);
			uint64_t peak = atomic_load_explicit(
			    &ctx->metrics->peak_memory[i], memory_order_relaxed);
			uint64_t cpu = atomic_load_explicit(&ctx->metrics->cpu_cycles[i],
			                                    memory_order_relaxed);

			// if (ctx->metrics->sample_counts[i] > 0)
			// 	avg_time = ctx->metrics->total_time_ns[i]
			// 	           / ctx->metrics->sample_counts[i];

			/* Use the loaded values in fprintf */
			fprintf(fp,
			        "%s,%lu,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
			        ctx->metrics->signatures[i],
			        (unsigned long)call_count,
			        0, // sample_count
			        (unsigned long)total_time,
			        (unsigned long)avg_time,
			        (unsigned long)(min_time == UINT64_MAX ? 0 : min_time),
			        (unsigned long)max_time,
			        (unsigned long)alloc,
			        (unsigned long)peak,
			        (unsigned long)cpu);

			total_calls += call_count;
			// total_samples += ctx->metrics->sample_counts[i];

			/* Debug output to verify each method's metrics */
			LOG_DEBUG("Method[%zu]: %s, calls=%lu, samples=%lu, time=%lu\n",
			          i,
			          ctx->metrics->signatures[i],
			          (unsigned long)ctx->metrics->call_counts[i],
			          0,
			          //   (unsigned long)ctx->metrics->sample_counts[i],
			          (unsigned long)ctx->metrics->total_time_ns[i]);
		}
	}

	/* Add heap stats section before summary */
	fprintf(fp, "# ------ \n\n");

	fprintf(fp,
	        "# Heap Statistics (Top %zu Classes by Memory Usage)\n",
	        ctx->last_heap_stats_count);
	fprintf(fp, "# Format: class_name, instance_count, total_size, avg_size\n");

	if (ctx->last_heap_stats && ctx->last_heap_stats_count > 0)
	{
		for (size_t i = 0; i < ctx->last_heap_stats_count; i++)
		{
			class_stats_t *stats =
			    (class_stats_t *)ctx->last_heap_stats->elements[i];
			if (stats && stats->class_name)
			{
				fprintf(fp,
				        "%s,%llu,%llu,%llu\n",
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

	LOG_INFO("Export complete: methods=%zu, calls=%lu, samples=%lu\n",
	         ctx->metrics->count,
	         (unsigned long)total_calls,
	         (unsigned long)total_samples);

	fclose(fp);
}

static void
export_method_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->metrics)
		return;

	for (size_t i = 0; i < ctx->metrics->count; i++)
	{
		if (ctx->metrics->signatures[i])
		{
			/* Create clean method data structure */
			cooper_method_data_t method_data = {0};

			strncpy(method_data.signature,
			        ctx->metrics->signatures[i],
			        COOPER_MAX_SIGNATURE_LEN - 1);
			method_data.signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';
			method_data.metric_flags = ctx->metrics->metric_flags[i];

			/* Load atomics */
			method_data.call_count = atomic_load_explicit(
			    &ctx->metrics->call_counts[i], memory_order_relaxed);
			// method_data.sample_count  = ctx->metrics->sample_counts[i];
			method_data.total_time_ns = atomic_load_explicit(
			    &ctx->metrics->total_time_ns[i], memory_order_relaxed);
			method_data.min_time_ns = atomic_load_explicit(
			    &ctx->metrics->min_time_ns[i], memory_order_relaxed);
			method_data.max_time_ns = atomic_load_explicit(
			    &ctx->metrics->max_time_ns[i], memory_order_relaxed);
			method_data.alloc_bytes = atomic_load_explicit(
			    &ctx->metrics->alloc_bytes[i], memory_order_relaxed);
			method_data.peak_memory = atomic_load_explicit(
			    &ctx->metrics->peak_memory[i], memory_order_relaxed);
			method_data.cpu_cycles = atomic_load_explicit(
			    &ctx->metrics->cpu_cycles[i], memory_order_relaxed);

			cooper_shm_write_data(
			    ctx->shm_ctx, COOPER_DATA_METHOD_METRIC, &method_data);
		}
	}
}

/**
 * Export memory samples to shared memory
 */
static void
export_memory_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->app_memory_metrics)
		return;

	cooper_memory_data_t memory_data = {0};

	pthread_mutex_lock(&ctx->app_memory_metrics->lock);

	/* Export latest process memory sample */
	if (ctx->app_memory_metrics->sample_count > 0)
	{
		size_t latest_idx =
		    (ctx->app_memory_metrics->sample_count - 1) % MAX_MEMORY_SAMPLES;

		memory_data.process_memory =
		    ctx->app_memory_metrics->process_memory_sample[latest_idx];

		cooper_shm_write_data(
		    ctx->shm_ctx, COOPER_DATA_MEMORY_SAMPLE, &memory_data);
	}

	/* Export thread memory samples */
	if (ctx->thread_mem_head != NULL)
	{
		thread_memory_metrics_t *tm = ctx->thread_mem_head;
		while (tm)
		{
			if (tm->sample_count > 0)
			{
				size_t latest_idx =
				    (tm->sample_count - 1) % MAX_MEMORY_SAMPLES;

				memory_data           = (cooper_memory_data_t){0};
				memory_data.thread_id = tm->thread_id;
				memory_data.thread_memory =
				    tm->memory_samples[latest_idx];

				cooper_shm_write_data(ctx->shm_ctx,
				                      COOPER_DATA_MEMORY_SAMPLE,
				                      &memory_data);
			}
			tm = tm->next;
		}
	}

	pthread_mutex_unlock(&ctx->app_memory_metrics->lock);
}

/**
 * Export object allocation metrics to shared memory
 */
static void
export_object_alloc_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->object_metrics)
		return;

	for (size_t i = 0; i < ctx->object_metrics->count; i++)
	{
		uint64_t alloc_count = ctx->object_metrics->allocation_counts[i];

		if (ctx->object_metrics->class_signatures[i] && alloc_count > 0)
		{

			/* Clean object allocation data */
			cooper_object_alloc_data_t alloc_data = {0};

			strncpy(alloc_data.class_signature,
			        ctx->object_metrics->class_signatures[i],
			        COOPER_MAX_SIGNATURE_LEN - 1);
			alloc_data.class_signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';

			alloc_data.allocation_count = alloc_count;
			alloc_data.current_instances =
			    ctx->object_metrics->current_instances[i];
			alloc_data.total_bytes = ctx->object_metrics->total_bytes[i];
			alloc_data.peak_instances =
			    ctx->object_metrics->peak_instances[i];
			alloc_data.min_size = ctx->object_metrics->min_size[i];
			alloc_data.max_size = ctx->object_metrics->max_size[i];
			alloc_data.avg_size = alloc_data.total_bytes / alloc_count;

			cooper_shm_write_data(
			    ctx->shm_ctx, COOPER_DATA_OBJECT_ALLOC, &alloc_data);
		}
	}
}

static void
export_heap_stats_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->last_heap_stats)
		return;

	if (!ctx->last_heap_stats || ctx->last_heap_stats_count == 0)
		return;

	for (size_t i = 0; i < ctx->last_heap_stats_count; i++)
	{
		class_stats_t *stats = (class_stats_t *)ctx->last_heap_stats->elements[i];

		if (!stats || !stats->class_name)
			continue;

		cooper_heap_stats_data_t heap_stats_data = {0};
		strncpy(heap_stats_data.class_signature,
		        stats->class_name,
		        COOPER_MAX_SIGNATURE_LEN - 1);
		heap_stats_data.class_signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';
		heap_stats_data.instance_count = stats->instance_count;
		heap_stats_data.total_sz       = stats->total_size;
		heap_stats_data.total_deep_sz  = stats->total_deep_size;
		heap_stats_data.avg_sz         = stats->avg_size;
		heap_stats_data.avg_deep_sz    = stats->avg_deep_size;

		cooper_shm_write_data(
		    ctx->shm_ctx, COOPER_DATA_HEAP_STATS, &heap_stats_data);
	}
}

// TODO complete this stub
static void
export_call_stack_samples_to_shm(agent_context_t *ctx)
{
	if (!ctx)
		return;
}

void *
flamegraph_export_thread(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;

	if (!ctx)
		return NULL;

	JNIEnv *jni = NULL;

	/* Attach this thread to the JVM to get a JNIEnv */
	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach flamegraph export thread to JVM, error: %d\n",
		          res);
		return NULL;
	}

	uint64_t file_start_ns = get_current_time_ns();
	FILE *out              = NULL;
	char filename[256];

	stack_bucket_t buckets[MAX_BUCKETS];
	size_t bucket_count = 0;

	snprintf(filename,
	         sizeof(filename),
	         "/tmp/flamegraph-%llu.txt",
	         (unsigned long long)file_start_ns);
	out = fopen(filename, "w");

	if (!out)
	{
		LOG_ERROR("Failed to open initial flamegraph output file: %s", filename);
		return NULL;
	}

	while (check_worker_status(ctx->tm_ctx.worker_statuses, CALL_STACK_RUNNING))
	{
		uint32_t idx;
		call_stack_sample_t *sample =
		    sample_consume(&ctx->call_stack_channel, &idx);

		if (!sample)
		{
			usleep(10000);
			continue;
		}

		char buf[8192];
		size_t pos           = 0;
		size_t valid_samples = 0;

		for (size_t f = 0; f < sample->frame_count; f++)
		{
			jmethodID mid = sample->frames[f];

			/* Find declaring class */
			jclass declaring_class;
			(*ctx->jvmti_env)
			    ->GetMethodDeclaringClass(
				ctx->jvmti_env, mid, &declaring_class);

			/* Lookup our cached class_info_t from tag */
			jlong tag;
			(*ctx->jvmti_env)->GetTag(ctx->jvmti_env, declaring_class, &tag);
			if (tag == 0)
				continue;

			cooper_class_info_t *info = (cooper_class_info_t *)(intptr_t)tag;

			/* Linear search for matching method_id (could later be a hash
			 * map) */
			cooper_method_info_t *mi = NULL;
			for (uint32_t m = 0; m < info->method_count; m++)
			{
				if (info->methods[m].method_id == mid)
				{
					mi = &info->methods[m];
					break;
				}
			}
			if (!mi || !mi->full_name)
				continue;

			int n = snprintf(buf + pos,
			                 sizeof(buf) - pos,
			                 "%s%s",
			                 mi->full_name,
			                 (f == sample->frame_count - 1) ? "" : ";");
			if (n < 0 || (size_t)n >= sizeof(buf) - pos)
				break; /* truncated */
			pos += n;
			valid_samples++;
		}

		if (valid_samples)
		{
			/* Aggregate into buckets */
			size_t i;
			for (i = 0; i < bucket_count; i++)
			{
				if (strcmp(buckets[i].stack_str, buf) == 0)
				{
					buckets[i].count++;
					break;
				}
			}

			if (i == bucket_count && bucket_count < MAX_BUCKETS)
			{
				buckets[bucket_count].stack_str =
				    arena_strdup(ctx->arenas[FLAMEGRAPH_ARENA_ID], buf);
				buckets[bucket_count].count = 1;
				bucket_count++;
			}
		}

		sample_release(&ctx->call_stack_channel, idx);

		/* Check for rollover */
		uint64_t now = get_current_time_ns();
		if (now - file_start_ns >= ROLL_INTERVAL)
		{
			/* Flush all buckets */
			for (size_t i = 0; i < bucket_count; i++)
				fprintf(out,
				        "%s %zu\n",
				        buckets[i].stack_str,
				        buckets[i].count);

			arena_reset(ctx->arenas[FLAMEGRAPH_ARENA_ID]);
			fclose(out);

			/* Reset buckets */
			bucket_count  = 0;
			file_start_ns = now;

			/* Open new file */
			snprintf(filename,
			         sizeof(filename),
			         "/tmp/flamegraph-%llu.txt",
			         (unsigned long long)file_start_ns);
			out = fopen(filename, "w");
			if (!out)
			{
				LOG_ERROR(
				    "Failed to open rollover flamegraph output file: %s",
				    filename);
				break;
			}
		}
	}

	/* Final flush */
	if (out)
	{
		for (size_t i = 0; i < bucket_count; i++)
			fprintf(out, "%s %zu\n", buckets[i].stack_str, buckets[i].count);

		arena_reset(ctx->arenas[FLAMEGRAPH_ARENA_ID]);
		fclose(out);
	}

	/* Detach from JVM */
	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Flamegraph export thread exiting");

	return NULL;
}

/**
 *
 */
static void
sample_thread_mem(agent_context_t *ctx, JNIEnv *jni, uint64_t timestamp)
{
	if (!jni || !ctx)
	{
		LOG_ERROR("Invalid context or JNI environment in sample_thread_mem");
		return;
	}

	jobject threadsMap   = NULL;
	jobject entrySet     = NULL;
	jobjectArray entries = NULL;
	jclass mapClass      = NULL;
	jclass setClass      = NULL;

	/* Get the getAllStackTraces method */
	jmethodID getAllThreadsMethod = (*jni)->GetStaticMethodID(
	    jni, ctx->java_thread_class, "getAllStackTraces", "()Ljava/util/Map;");
	if (!getAllThreadsMethod)
	{
		LOG_ERROR("Failed to find getAllStackTraces method\n");
		goto cleanup;
	}

	/* Call getAllStackTraces to get all threads */
	threadsMap = (*jni)->CallStaticObjectMethod(
	    jni, ctx->java_thread_class, getAllThreadsMethod);
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

	jmethodID entrySetMethod =
	    (*jni)->GetMethodID(jni, mapClass, "entrySet", "()Ljava/util/Set;");
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

	jmethodID toArrayMethod =
	    (*jni)->GetMethodID(jni, setClass, "toArray", "()[Ljava/lang/Object;");
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

	/* Process each java live thread */
	for (int j = 0; j < num_threads; j++)
	{
		jobject entry     = NULL;
		jobject threadObj = NULL;
		jclass entryClass = NULL;

		entry = (*jni)->GetObjectArrayElement(jni, entries, j);
		if (!entry)
			continue;

		/* Get the key (Thread object) from the entry */
		entryClass = (*jni)->GetObjectClass(jni, entry);
		if (!entryClass)
			goto local_clean;

		jmethodID getKeyMethod = (*jni)->GetMethodID(
		    jni, entryClass, "getKey", "()Ljava/lang/Object;");
		if (!getKeyMethod)
			goto local_clean;

		threadObj = (*jni)->CallObjectMethod(jni, entry, getKeyMethod);
		if (!threadObj)
			goto local_clean;

		/* Get thread ID */
		jlong thread_id =
		    (*jni)->CallLongMethod(jni, threadObj, ctx->getId_method);
		if ((*jni)->ExceptionCheck(jni))
		{
			(*jni)->ExceptionClear(jni);
			goto local_clean;
		}

		/* Get native thread ID */
		pid_t native_tid = get_native_thread_id(ctx, jni, threadObj);
		if (native_tid == 0)
			goto local_clean;

		/* Sample linux thread memory */
		uint64_t thread_mem = get_thread_memory(native_tid);
		if (thread_mem == 0)
			continue;

		thread_memory_metrics_t *thread_metrics = ctx->thread_mem_head;
		int found                               = 0;

		/* Look for existing metrics for this thread */
		while (thread_metrics)
		{
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
			thread_metrics = arena_alloc(ctx->arenas[METRICS_ARENA_ID],
			                             sizeof(thread_memory_metrics_t));
			if (thread_metrics)
			{
				thread_metrics->thread_id = thread_id;
				thread_metrics->next      = ctx->thread_mem_head;
				ctx->thread_mem_head      = thread_metrics;
				LOG_INFO("Created new thread memory metrics for "
				         "thread %lld",
				         (long long)thread_id);
			}
		}

		/* Store the memory sample */
		if (thread_metrics)
		{
			size_t idx = thread_metrics->sample_count % MAX_MEMORY_SAMPLES;
			thread_metrics->memory_samples[idx] = thread_mem;
			thread_metrics->timestamps[idx]     = timestamp;
			thread_metrics->sample_count++;

			LOG_DEBUG("Stored memory sample for thread %lld: %llu bytes",
			          (long long)thread_id,
			          (unsigned long long)thread_mem);
		}

	local_clean:
		/* Clean up local references */
		if (threadObj)
			(*jni)->DeleteLocalRef(jni, threadObj);
		if (entryClass)
			(*jni)->DeleteLocalRef(jni, entryClass);
		if (entry)
			(*jni)->DeleteLocalRef(jni, entry);
	}

cleanup:
	/* Clean up all JNI local references */
	if (entries)
		(*jni)->DeleteLocalRef(jni, entries);
	if (setClass)
		(*jni)->DeleteLocalRef(jni, setClass);
	if (entrySet)
		(*jni)->DeleteLocalRef(jni, entrySet);
	if (mapClass)
		(*jni)->DeleteLocalRef(jni, mapClass);
	if (threadsMap)
		(*jni)->DeleteLocalRef(jni, threadsMap);
}

/* Comparison function for class stats (by total_size) */
static int
class_stats_compare(const void *a, const void *b)
{
	const class_stats_t *stats_a = (const class_stats_t *)a;
	const class_stats_t *stats_b = (const class_stats_t *)b;

	if (stats_a->total_size < stats_b->total_size)
		return -1;
	if (stats_a->total_size > stats_b->total_size)
		return 1;
	return 0;
}

static class_stats_t *
find_or_create_stats(heap_iteration_context_t *heap_ctx, const char *class_sig)
{

	assert(heap_ctx != NULL);
	assert(heap_ctx->class_table != NULL);
	assert(class_sig != NULL);

	/* Additional validation */
	if (!class_sig || class_sig[0] == '\0')
		return NULL;

	/* Try to find existing stats using API */
	class_stats_t *stats = (class_stats_t *)ht_get(heap_ctx->class_table, class_sig);
	if (stats)
		return stats; /* Found existing entry */

	/* Check load factor before creating new entry */
	if (ht_get_load(heap_ctx->class_table) >= 0.75)
	{
		LOG_ERROR("Hash table load factor exceeded");
		return NULL;
	}

	/* Create new stats entry - stats will be memset to 0 by arena */
	stats =
	    arena_alloc_aligned(heap_ctx->arena, sizeof(class_stats_t), CACHE_LINE_SZ);
	if (!stats)
	{
		LOG_ERROR("Failed to allocate class stats");
		return NULL;
	}

	/* Add to hashtable using API */
	if (ht_put(heap_ctx->class_table, class_sig, stats) != COOPER_OK)
	{
		LOG_ERROR("Failed to add class stats to hashtable");
		return NULL;
	}

	LOG_DEBUG("Created new hash entry for class '%s' (load: %.2f)",
	          class_sig,
	          ht_get_load(heap_ctx->class_table));
	return stats;
}

static uint64_t
est_deep_sz(const char *class_sig, uint64_t shallow_size)
{
	for (size_t i = 0; i < sizeof(deep_sz_cfgs) / sizeof(deep_sz_cfgs[0]); i++)
	{
		if (strstr(class_sig, deep_sz_cfgs[i].pattern))
			return (shallow_size * deep_sz_cfgs[i].mult)
			       + deep_sz_cfgs[i].overhead_bytes;
	}

	/* Conservative default */
	return shallow_size * 2;
}

static jint JNICALL
heap_object_callback(
    jlong class_tag, jlong size, jlong *tag_ptr, jint length, void *user_data)
{
	UNUSED(tag_ptr);
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

	heap_iteration_context_t *ctx = (heap_iteration_context_t *)user_data;

	/* Validate context */
	if (!ctx->class_table)
	{
		LOG_ERROR("Invalid context in heap callback");
		return JVMTI_VISIT_ABORT;
	}

	/* class_tag should be a pointer to class_info_t struct */
	cooper_class_info_t *info = (cooper_class_info_t *)(intptr_t)class_tag;
	if (!info->in_heap_iteration)
	{
		LOG_DEBUG("Class %s not in iteration", info->class_sig);
		return JVMTI_VISIT_OBJECTS;
	}

	/* Update class statistics (shallow size) */
	class_stats_t *stats = find_or_create_stats(ctx, info->class_sig);
	if (!stats)
		return JVMTI_VISIT_OBJECTS;

	/* Overflow protection for counters */
	if (stats->instance_count == UINT64_MAX)
	{
		LOG_WARN("Instance count overflow for class_tag %ld", class_tag);
		return JVMTI_VISIT_OBJECTS;
	}

	uint64_t safe_size = (uint64_t)size; /* Convert after validation */
	if (stats->total_size > UINT64_MAX - safe_size)
	{
		LOG_WARN("Total size overflow for class_tag %ld", class_tag);
		return JVMTI_VISIT_OBJECTS;
	}

	/* Update shallow size statistics */
	stats->instance_count++;
	stats->total_size += safe_size;

	/* Safe average calculation */
	if (stats->instance_count > 0)
		stats->avg_size = stats->total_size / stats->instance_count;

	uint64_t estimated_deep_size = safe_size;

	/* Apply class-specific multipliers based on class signature */
	if (info->class_sig[0] == '[')
	{
		if (strstr(info->class_sig, "[L"))
		{
			/* Object arrays – references dominate */
			estimated_deep_size = safe_size * 2;
		}
		else
		{
			/* Primitive arrays – low overhead */
			estimated_deep_size = safe_size + (safe_size / 8);
		}
	}
	else
		estimated_deep_size = est_deep_sz(info->class_sig, safe_size);

	/* Update deep size statistics */
	stats->total_deep_size += estimated_deep_size;
	if (stats->instance_count > 0)
		stats->avg_deep_size = stats->total_deep_size / stats->instance_count;

	LOG_DEBUG("Object: %s, shallow: %lu, estimated_deep: %lu, total_deep: %lu",
	          info->class_sig,
	          safe_size,
	          estimated_deep_size,
	          stats->total_deep_size);

	return JVMTI_VISIT_OBJECTS;
}

/* */
static void
collect_heap_statistics(agent_context_t *ctx, JNIEnv *env)
{
	/* Reset scratch arena to reclaim previous allocations */
	arena_reset(ctx->arenas[HEAP_STATS_ARENA_ID]);

	/* Clear previous heap stats as these are now invalid */
	ctx->last_heap_stats       = NULL;
	ctx->last_heap_stats_count = 0;

	// TODO move to config
	const size_t TOP_N = 20;

	/* Get loaded classes with error handling */
	int class_count;
	jclass *classes;
	jvmtiEnv *jvmti = ctx->jvmti_env;
	jvmtiError err  = (*jvmti)->GetLoadedClasses(jvmti, &class_count, &classes);
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
	min_heap_t *heap =
	    min_heap_create(ctx->arenas[HEAP_STATS_ARENA_ID], TOP_N, class_stats_compare);
	if (!heap)
	{
		LOG_ERROR("Failed to create min heap");
		goto cleanup_classes;
	}

	/* Create generic hashtable for class statistics */
	hashtable_t *class_ht = ht_create(ctx->arenas[HEAP_STATS_ARENA_ID],
	                                  MAX_HASH_SIZE,
	                                  0.75,
	                                  hash_string,
	                                  cmp_string);

	if (!class_ht)
	{
		LOG_ERROR("Failed to create hashtable");
		goto cleanup_classes;
	}

	/* Set up iteration context with validation */
	heap_iteration_context_t iter_ctx = {.env   = env,
	                                     .jvmti = jvmti,
	                                     .arena = ctx->arenas[HEAP_STATS_ARENA_ID],
	                                     .class_table = class_ht};

	/* Tag classes for heap iteration */
	for (int i = 0; i < class_count; i++)
	{
		jlong tag = 0;
		(*jvmti)->GetTag(jvmti, classes[i], &tag);

		if (tag != 0)
		{
			cooper_class_info_t *info = (cooper_class_info_t *)(intptr_t)tag;
			info->in_heap_iteration   = 1;
		}
	}
	LOG_INFO("Starting heap analysis");
	jvmtiHeapCallbacks callbacks      = {0};
	callbacks.heap_iteration_callback = heap_object_callback;

	err = (*jvmti)->IterateThroughHeap(jvmti, 0, NULL, &callbacks, &iter_ctx);
	if (err != JVMTI_ERROR_NONE)
	{
		LOG_ERROR("IterateThroughHeap failed: %d", err);
		goto cleanup_tags;
	}

	LOG_INFO("Heap analysis completed. Classes: %zu", iter_ctx.class_table->count);

	/* Process hashtable results into top-N heap with bounds checking */
	size_t processed = 0;

	for (size_t i = 0; i < iter_ctx.class_table->capacity
	                   && processed < iter_ctx.class_table->count;
	     i++)
	{
		ht_entry_t *entry = &iter_ctx.class_table->entries[i];

		/* CRITICAL: Check if entry is occupied before accessing value */
		if (entry->state != HT_OCCUPIED || !entry->value)
			continue; /* Skip empty slots */

		class_stats_t *stats = (class_stats_t *)entry->value;

		if (stats->instance_count == 0)
			continue; /* Nothing to do here */

		processed++;

		/* DLog stats before adding to heap */
		LOG_DEBUG("Final stats for %s: instances=%llu, shallow_total=%llu, "
		          "deep_total=%llu",
		          entry->key,
		          (unsigned long long)stats->instance_count,
		          (unsigned long long)stats->total_size,
		          (unsigned long long)stats->total_deep_size);

		uint64_t sort_size = (stats->total_deep_size > 0) ? stats->total_deep_size
		                                                  : stats->total_size;

		/* Only resolve names for potential top-N entries */
		if (heap->size < TOP_N
		    || sort_size > ((class_stats_t *)heap->elements[0])->total_deep_size)
		{
			class_stats_t *heap_entry = arena_alloc(
			    ctx->arenas[HEAP_STATS_ARENA_ID], sizeof(class_stats_t));
			if (!heap_entry)
			{
				LOG_WARN("Failed to allocate heap entry %zu", i);
				continue;
			}

			/* Copy stats */
			*heap_entry = *stats;
			heap_entry->class_name =
			    arena_strdup(ctx->arenas[HEAP_STATS_ARENA_ID], entry->key);

			/* Without a class name nothing to do */
			if (!heap_entry->class_name)
				continue;

			/* Insert into min heap */
			if (!min_heap_insert_or_replace(heap, heap_entry))
			{
				LOG_DEBUG("Failed to insert into heap (likely "
				          "not top-N)");
			}
			else
			{
				LOG_DEBUG("Added to heap: %s (%llu instances, %llu "
				          "bytes)",
				          heap_entry->class_name,
				          (unsigned long long)heap_entry->instance_count,
				          (unsigned long long)heap_entry->total_size);
			}
		}
	}

	LOG_INFO("Processed %zu classes, top heap size: %zu", processed, heap->size);

	ctx->last_heap_stats       = heap;
	ctx->last_heap_stats_count = heap->size;
	ctx->last_heap_stats_time  = get_current_time_ns();
	LOG_DEBUG("Stored heap statistics: %zu classes at time %llu",
	          heap->size,
	          (unsigned long long)ctx->last_heap_stats_time);

cleanup_tags:
	/* Clean up class tags */
	for (int i = 0; i < class_count; i++)
	{
		jlong tag = 0;
		(*jvmti)->GetTag(jvmti, classes[i], &tag);

		if (tag != 0)
		{
			cooper_class_info_t *info = (cooper_class_info_t *)(intptr_t)tag;
			info->in_heap_iteration   = 0;
		}
	}

cleanup_classes:
	(*jvmti)->Deallocate(jvmti, (unsigned char *)classes);
}

/**
 * Register a class for object allocation tracking
 *
 * @return index into obj_metrics array or -1 on failure
 */
static int
register_object_type(object_allocation_metrics_t *obj_metrics,
                     arena_t *arena,
                     const char *class_sig)
{
	assert(obj_metrics != NULL);
	assert(arena != NULL);

	if (obj_metrics->count >= obj_metrics->capacity)
	{
		LOG_WARN("Object metrics capacity reached (%zu)\n",
		         obj_metrics->capacity);
		return -1;
	}

	/* We just use the next slot based on the metrics count as the new idx */
	int32_t idx = obj_metrics->count;

	obj_metrics->class_signatures[idx] = arena_strdup(arena, class_sig);
	if (!obj_metrics->class_signatures[idx])
	{
		LOG_ERROR("Failed to allocation mem for class signature: %s\n",
		          class_sig);
		return -1;
	}

	obj_metrics->min_size[idx] = UINT64_MAX;
	obj_metrics->count++;

	LOG_DEBUG("Registered object type: %s at index: %d (total types: %zu)\n",
	          class_sig,
	          idx,
	          obj_metrics->count);
	return idx;
}

/* Caches class and method info using SetTag */
static void
cache_class_info(agent_context_t *ctx,
                 arena_t *arena,
                 jvmtiEnv *jvmti_env,
                 JNIEnv *jni_env,
                 jclass klass)
{
	assert(jvmti_env != NULL);
	assert(jni_env != NULL);

	char *class_sig    = NULL;
	jmethodID *methods = NULL;
	jvmtiError err =
	    (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);

	if (err != JVMTI_ERROR_NONE || class_sig == NULL)
		goto deallocate;

	/* Get all methods for the class */
	jint method_count = 0;
	err = (*jvmti_env)->GetClassMethods(jvmti_env, klass, &method_count, &methods);

	if (err != JVMTI_ERROR_NONE)
		goto deallocate;

	/* We only care about classes with methods */
	if (method_count == 0)
		goto deallocate;

	/* Calculate total size needed for class info and methods array */
	size_t total_size =
	    sizeof(cooper_class_info_t) + (sizeof(cooper_method_info_t) * method_count);

	/* Allocate the main class_info struct and methods array in one go */
	cooper_class_info_t *info = arena_alloc(arena, total_size);
	if (info == NULL)
		goto deallocate;

	/* Create GlobalRef for this class - this survives across threads */
	info->global_ref = (*jni_env)->NewGlobalRef(jni_env, klass);
	if (!info->global_ref)
	{
		LOG_ERROR("Failed to create GlobalRef for class %s", class_sig);
		goto deallocate;
	}

	strncpy(info->class_sig, class_sig, sizeof(info->class_sig) - 1);
	info->in_heap_iteration = 0;

	/* Register this class for object allocation tracking in the SoA struct.
       This must happen before SetTag, so that obj_alloc_index is visible
       to any thread that later reads the tag. */
	int obj_idx = register_object_type(
	    ctx->object_metrics, ctx->arenas[METRICS_ARENA_ID], class_sig);
	info->obj_alloc_index = (obj_idx >= 0) ? (int32_t)obj_idx : -1;

	/* Set up the methods pointer to point to the memory immediately following the
	 * struct */
	info->methods      = (cooper_method_info_t *)(info + 1);
	info->method_count = method_count;

	/* Loop through each method and cache details */
	for (int i = 0; i < method_count; i++)
	{
		char *method_name = NULL;
		char *method_sig  = NULL;

		/* Skip any method where we cannot get name */
		if ((*jvmti_env)
		        ->GetMethodName(
			    jvmti_env, methods[i], &method_name, &method_sig, NULL)
		    != JVMTI_ERROR_NONE)
			continue;

		/* Check if this specific method matches any filter */
		pattern_filter_entry_t *matching_filter = find_matching_filter(
		    &ctx->unified_filter, class_sig, method_name, method_sig);

		if (!matching_filter)
			goto next_method;

		/* Mark method as not interesting first */
		info->methods[i].sample_index = -1;

		char buf[1024];
		info->methods[i].method_id = methods[i];
		/* Store arena-allocated copies of the names */
		info->methods[i].method_name      = arena_strdup(arena, method_name);
		info->methods[i].method_signature = arena_strdup(arena, method_sig);
		snprintf(buf, sizeof(buf), "%s.%s", class_sig, method_name);
		info->methods[i].full_name = arena_strdup(arena, buf);

		/* Build full signature for metrics structure */
		char full_sig[1024];
		int written = snprintf(full_sig,
		                       sizeof(full_sig),
		                       "%s %s %s",
		                       class_sig,
		                       method_name,
		                       method_sig);

		if (written < 0 || written >= (int)sizeof(full_sig))
		{
			LOG_ERROR("Method signature too long: %s:%s:%s\n",
			          class_sig,
			          method_name,
			          method_sig);
			goto next_method;
		}

		/* Add method to metrics structure using filter configuration */
		int sample_index = add_method_to_metrics(ctx,
		                                         full_sig,
		                                         matching_filter->sample_rate,
		                                         matching_filter->metric_flags);

		/* Only add interesting methods to cache */
		if (sample_index < 0)
			goto next_method;

		info->methods[i].sample_index = sample_index;

		/* Add to interesting methods hashtable */
		if (ht_put(ctx->interesting_methods,
		           info->methods[i].method_id,
		           &info->methods[i])
		    != COOPER_OK)
		{
			LOG_WARN("Failed to cache method %s",
			         info->methods[i].method_name);
		}
		else
		{
			LOG_DEBUG("Cached method: %s (sample_rate=%d, "
			          "flags=%u, index=%d)",
			          info->methods[i].full_name,
			          matching_filter->sample_rate,
			          matching_filter->metric_flags,
			          sample_index);
		}

	next_method:
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_name);
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_sig);
	}

	/* Set the tag */
	jlong tag = (jlong)(intptr_t)info;
	err       = (*jvmti_env)->SetTag(jvmti_env, klass, tag);
	if (err != JVMTI_ERROR_NONE)
		LOG_ERROR("Failed to set tag for class %s, error: %d", class_sig, err);

	/* Add to class_info_by_name hashtable for lookup by class name string.
	   Note: We use info->class_sig as the key since it's arena-allocated and
	   persists for the lifetime of the agent. */
	if (ht_put(ctx->class_info_by_name, info->class_sig, info) != COOPER_OK)
		LOG_WARN("Failed to add class %s to name lookup hashtable", class_sig);

deallocate:
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)class_sig);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)methods);
}

/* Thread functions */

void *
export_thread_func(void *arg)
{
	assert(arg != NULL);

	agent_context_t *ctx = (agent_context_t *)arg;

	LOG_INFO("Export thread started, interval=%d seconds\n",
	         ctx->config.export_interval);

	/* Initial export to create the file */
	export_to_file(ctx);

	/* export to file while export_running flag is set */
	while (check_worker_status(ctx->tm_ctx.worker_statuses, EXPORT_RUNNING))
	{
		/* Sleep in smaller increments to be more responsive to shutdown */
		for (int i = 0;
		     i < ctx->config.export_interval
		     && check_worker_status(ctx->tm_ctx.worker_statuses, EXPORT_RUNNING);
		     i++)
			sleep(1);

		if (check_worker_status(ctx->tm_ctx.worker_statuses, EXPORT_RUNNING))
		{
			LOG_INFO("Export thread woke up, exporting metrics\n");
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
void *
shm_export_thread_func(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;

	LOG_INFO("Shared memory export thread started");

	/* TODO move export interval to const */
	while (check_worker_status(ctx->tm_ctx.worker_statuses, SHM_EXPORT_RUNNING))
	{
		if (ctx->shm_ctx == NULL || ctx->shm_ctx->status_shm == NULL)
		{
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

		/* Export heap stats */
		export_heap_stats_to_shm(ctx);

		/* Export call stack samples */
		export_call_stack_samples_to_shm(ctx);

		/* Sleep for export interval */
		sleep(2);
	}

	LOG_INFO("Shared memory export thread terminated");
	return NULL;
}

/**
 *
 */
void *
mem_sampling_thread_func(void *arg)
{
	assert(arg != NULL);

	agent_context_t *ctx = (agent_context_t *)arg;
	LOG_INFO("Memory sampling thread started, interval=%d seconds\n",
	         ctx->config.mem_sample_interval);

	JNIEnv *jni = NULL;

	/* Attach this thread to the JVM to get a JNIEnv */
	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach memory sampling thread to JVM, error: %d\n",
		          res);
		return NULL;
	}

	LOG_INFO("Memory sampling thread successfully attached to JVM");

	while (check_worker_status(ctx->tm_ctx.worker_statuses, MEM_SAMPLING_RUNNING))
	{
		/* Get current timestamp for this sample */
		uint64_t timestamp = get_current_time_ns();

		/* Sample process memory */
		uint64_t process_mem = get_process_memory();
		if (process_mem > 0)
		{
			pthread_mutex_lock(&ctx->app_memory_metrics->lock);

			/* Use circular buffer pattern if we reach maximum samples */
			size_t idx =
			    ctx->app_memory_metrics->sample_count % MAX_MEMORY_SAMPLES;
			ctx->app_memory_metrics->process_memory_sample[idx] = process_mem;
			ctx->app_memory_metrics->timestamps[idx]            = timestamp;
			ctx->app_memory_metrics->sample_count++;

			pthread_mutex_unlock(&ctx->app_memory_metrics->lock);

			// LOG_DEBUG("Memory sample #%zu: %llu bytes at %llu ns",
			//           ctx->app_memory_metrics->sample_count,
			//           (unsigned long long)process_mem,
			//           (unsigned long long)timestamp);
		}

		/* Sample thread memory for active Java threads */
		sample_thread_mem(ctx, jni, timestamp);

		/* Sleep for the configured interval */
		sleep(ctx->config.mem_sample_interval);
	}

	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Memory sampling thread terminated\n");
	return NULL;
}

/* Heap stats collection thread func */
void *
heap_stats_thread_func(void *arg)
{
	assert(arg != NULL);

	agent_context_t *ctx = (agent_context_t *)arg;

	LOG_INFO("Heap statistics thread started, interval=60 seconds\n");

	JNIEnv *jni = NULL;

	/* Attach this thread to the JVM to get a JNIEnv */
	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach heap statistics thread to JVM, error: %d\n",
		          res);
		return NULL;
	}

	LOG_INFO("Heap statistics thread successfully attached to JVM");

	// TODO extract sleep interval to config
	while (check_worker_status(ctx->tm_ctx.worker_statuses, HEAP_STATS_RUNNING))
	{
		/* Collect heap statistics */
		collect_heap_statistics(ctx, jni);

		/* Sleep for 60 seconds between collections */
		sleep(60);
	}

	/* Detach from JVM */
	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Heap statistics thread terminated\n");
	return NULL;
}

/**
 * Class caching thread function
 */
void *
class_cache_thread_func(void *arg)
{
	assert(arg != NULL);

	agent_context_t *ctx = (agent_context_t *)arg;
	arena_t *arena       = ctx->arenas[CLASS_CACHE_ARENA_ID];

	/* Get JNI environment for this thread */
	JNIEnv *jni = NULL;

	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach class cache thread to JVM");
		return NULL;
	}
#ifdef ENABLE_DEBUG_LOGS
	int classes_processed = 0;
#endif
	LOG_INFO("Class cache thread started");

	while (check_worker_status(ctx->tm_ctx.worker_statuses, CLASS_CACHE_RUNNING))
	{
		uint32_t handle;
		if (mpsc_ring_consume(&ctx->class_ring, &handle) != 0)
		{
			/* Ring empty */
			usleep(10000); /* Sleep for 10ms */
			continue;
		}

		void *buffer = mpsc_ring_get(&ctx->class_ring, handle);
		if (!buffer)
		{
			mpsc_ring_release(&ctx->class_ring, handle);
			continue;
		}

		serialized_class_event_t *event = (serialized_class_event_t *)buffer;

#ifdef ENABLE_DEBUG_LOGS
		classes_processed++;
		LOG_DEBUG("Processing class #%d from ring", classes_processed);
#endif
		cache_class_info(ctx, arena, ctx->jvmti_env, jni, event->klass);

		/* Delete the global reference after processing */
		(*jni)->DeleteGlobalRef(jni, event->klass);

		mpsc_ring_release(&ctx->class_ring, handle);
	}

	/* Detach from JVM */
	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Class cache thread exiting");
	return NULL;
}

/**
 *
 */
void *
call_stack_sampling_thread_func(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;
	jvmtiEnv *jvmti      = ctx->jvmti_env;
	jvmtiError err;

	/* Get JNI environment for this thread */
	JNIEnv *jni = NULL;
	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach call stack sampling thread to JVM");
		return NULL;
	}

	while (check_worker_status(ctx->tm_ctx.worker_statuses, CALL_STACK_RUNNING))
	{
		// TODO decouple the thread func from the body...
		//  sleep for configured interval
		//  usleep(ctx->config.stack_sample_interval * 1000); // e.g. 10ms
		usleep(10000); // TODO move this to config - right now 100ms seems
		               // reasonable

		/* Get all threads */
		jint thread_count = 0;
		jthread *threads  = NULL;
		err = (*jvmti)->GetAllThreads(jvmti, &thread_count, &threads);
		if (err != JVMTI_ERROR_NONE)
			continue;

		/* We get the time before looping so that all the samples
		are taken "at the same time"...
		*/
		uint64_t now = get_current_time_ns();
		jvmtiFrameInfo frames[MAX_STACK_FRAMES];

		for (int i = 0; i < thread_count; i++)
		{
			jint count = 0;

			/* If we cannot get the stack trace or count we just continue */
			err = (*jvmti)->GetStackTrace(
			    jvmti, threads[i], 0, MAX_STACK_FRAMES, frames, &count);
			if (err != JVMTI_ERROR_NONE || count == 0)
				continue;

			/* Allocate sample */
			uint32_t idx;
			call_stack_sample_t *sample =
			    sample_alloc(&ctx->call_stack_channel, &idx);

			if (!sample)
				continue; /* no free slot on channel ring */

			sample->timestamp_ns = now;
			sample->frame_count  = count;

			/* get thread id (cached Thread.getId) */
			jlong tid =
			    (*jni)->CallLongMethod(jni, threads[i], ctx->getId_method);
			sample->thread_id = tid;

			for (int f = 0; f < count; f++)
				sample->frames[f] = frames[f].method;

			/* Aggregate samples */
			for (int f = 0; f < count; f++)
			{
				jmethodID mid = sample->frames[f];

				// find cached info
				cooper_method_info_t *mi =
				    ht_get(ctx->interesting_methods, mid);

				if (!mi || mi->sample_index < 0)
					continue;

				atomic_fetch_add_explicit(
				    &ctx->metrics->call_sample_counts[mi->sample_index],
				    1,
				    memory_order_relaxed);
			}

			/* Publish to channel ready ring */
			sample_publish(&ctx->call_stack_channel, idx);
		}

		(*jvmti)->Deallocate(jvmti, (unsigned char *)threads);
	}

	/* Detach from JVM */
	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Call stack sampling thread exiting");

	return NULL;
}

/* Create a new sample on METHOD_ENTRY */
static void
record_method_entry_event(agent_context_t *ctx,
                          serialized_method_event_t *event,
                          jmethodID mid)
{
	assert(ctx != NULL);
	assert(event != NULL);

	/* Chomp the class_name that comes first, we don't use it */
	// char *class_name  = event->data;
	char *method_name = event->data + event->class_name_len + 1;

	/* Lookup method info from hashtable via jmethodID */
	cooper_method_info_t *method_info = ht_get(ctx->interesting_methods, mid);

	/* We either didn't find the method (should be rare) or it's not
	one we're configured to sample. */
	if (method_info == NULL)
	{
		LOG_DEBUG("Method info not found for mid %p (%s)", mid, method_name);
		return;
	}

	if (method_info->sample_index < 0)
	{
		LOG_DEBUG("Method %s not sampled (index %d)",
		          method_name,
		          method_info->sample_index);
		return;
	}

	LOG_DEBUG("Found method: %s in interesting_methods hashtable (index %d)",
	          method_info->full_name,
	          method_info->sample_index);

	/* We found a method to track. Atomically increment its total call count. */
	uint64_t current_calls = atomic_fetch_add_explicit(
	    &ctx->metrics->call_counts[method_info->sample_index],
	    1,
	    memory_order_relaxed);

	int sample_rate =
	    ctx->metrics
		->sample_rates[method_info->sample_index]; /* Read-only after init */

	/* Decide whether to sample this specific call based on the rate. */
	if ((current_calls % sample_rate) != 0)
		return; /* Don't sample this call. */

	thread_context_t *tc = get_thread_local_context();
	if (!tc)
	{
		LOG_ERROR("Unable to get thread context for %s, skipping", method_name);
		return;
	}

	if (tc->stack_depth >= MAX_STACK_FRAMES)
	{
		LOG_WARN("Method sample stack overflow for %s, skipping", method_name);
		return;
	}

	/* Use fixed array slot */
	method_sample_t *sample = &tc->samples[tc->stack_depth];

	sample->method_index = method_info->sample_index;
	sample->method_id    = mid;

	unsigned int flags = ctx->metrics->metric_flags[method_info->sample_index];

	if (flags & METRIC_FLAG_TIME)
		sample->start_time = event->timestamp;

	if (flags & METRIC_FLAG_CPU)
		sample->start_cpu = event->cpu;

	tc->stack_depth++;
}

/* Update an existing sample on METHOD_EXIT */
static void
record_method_exit_event(agent_context_t *ctx,
                         serialized_method_event_t *event,
                         jmethodID mid)
{
	assert(ctx != NULL);
	assert(event != NULL);

	/* Get thread-local context */
	thread_context_t *context = get_thread_local_context();

	/* Without a thread context, nothing we can do */
	if (!context)
		return;

	method_sample_t *target = NULL;
	int target_idx          = -1;

	/* We need to look in our stack to find a corresponding method
	entry Note that the JVM doesn't guarantee ordering of method
	entry/exits for a variety of reasons:
	- Threading
	- Optimizations
	- etc
	*/

	/* Search from the top of the stack of samples */
	for (int i = context->stack_depth - 1; i >= 0; i--)
	{
		if (context->samples[i].method_id == mid)
		{
			target     = &context->samples[i];
			target_idx = i;
			break;
		}
	}

	if (!target)
		return;

	/* Mark slot as empty by zeroing method_id, or compact the array.
	 * For simplicity, just decrement stack_depth if it's the top */
	if (target_idx == context->stack_depth - 1)
		context->stack_depth--;
	else
	{
		/* Move remaining items down to fill the gap (compact) */
		for (int i = target_idx; i < context->stack_depth - 1; i++)
			context->samples[i] = context->samples[i + 1];

		context->stack_depth--;
	}

	unsigned int flags = 0;

	if (target->method_index >= 0
	    && (size_t)target->method_index < ctx->metrics->count)
		flags = ctx->metrics->metric_flags[target->method_index];

	/* With no flags set, we have nothing to do */
	if (flags == 0)
		return;

	int method_idx = target->method_index;

	/* Calculate execution time */
	if ((flags & METRIC_FLAG_TIME) && target->start_time > 0)
	{
		uint64_t end_time  = event->timestamp;
		uint64_t exec_time = end_time - target->start_time;

		atomic_fetch_add_explicit(&ctx->metrics->total_time_ns[method_idx],
		                          exec_time,
		                          memory_order_relaxed);

		/* Update min/max using relaxed atomics
		We do not have a TOCTOU issue here as this function is called in a single
		background thread
		*/
		uint64_t current_min = atomic_load_explicit(
		    &ctx->metrics->min_time_ns[method_idx], memory_order_relaxed);
		if (exec_time < current_min)
		{
			atomic_store_explicit(&ctx->metrics->min_time_ns[method_idx],
			                      exec_time,
			                      memory_order_relaxed);
		}

		uint64_t current_max = atomic_load_explicit(
		    &ctx->metrics->max_time_ns[method_idx], memory_order_relaxed);
		if (exec_time > current_max)
		{
			atomic_store_explicit(&ctx->metrics->max_time_ns[method_idx],
			                      exec_time,
			                      memory_order_relaxed);
		}
	}

	if (flags & METRIC_FLAG_MEMORY)
	{
		uint64_t memory_delta = target->current_alloc_bytes;

		atomic_fetch_add_explicit(&ctx->metrics->alloc_bytes[method_idx],
		                          memory_delta,
		                          memory_order_relaxed);

		/* Update peak memory - no mutex needed */
		uint64_t current_peak = atomic_load_explicit(
		    &ctx->metrics->peak_memory[method_idx], memory_order_relaxed);
		if (memory_delta > current_peak)
		{
			atomic_store_explicit(&ctx->metrics->peak_memory[method_idx],
			                      memory_delta,
			                      memory_order_relaxed);
		}
	}

	if (flags & METRIC_FLAG_CPU)
	{
		uint64_t end_cpu   = event->cpu;
		uint64_t cpu_delta = 0;

		if (end_cpu > target->start_cpu)
			cpu_delta = end_cpu - target->start_cpu;
		else
			LOG_DEBUG("Invalid CPU cycles: end=%llu, start=%llu",
			          (unsigned long long)end_cpu,
			          (unsigned long long)target->start_cpu);

		atomic_fetch_add_explicit(&ctx->metrics->cpu_cycles[method_idx],
		                          cpu_delta,
		                          memory_order_relaxed);
	}
}

/**
 *
 */
void *
method_event_thread_func(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;

	/* Get JNI environment for this thread */
	JNIEnv *jni = NULL;

	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach method event thread to JVM");
		return NULL;
	}

	LOG_DEBUG("Method event thread started");

	while (check_worker_status(ctx->tm_ctx.worker_statuses, METHOD_EVENTS_RUNNING))
	{
		uint32_t handle;
		if (mpsc_ring_consume(&ctx->method_ring, &handle) != 0)
		{
			/* Ring empty */
			usleep(1000); /* Sleep for 1ms */
			continue;
		}

		void *buffer = mpsc_ring_get(&ctx->method_ring, handle);
		if (!buffer)
		{
			mpsc_ring_release(&ctx->method_ring, handle);
			continue;
		}

		serialized_method_event_t *event = (serialized_method_event_t *)buffer;
		char *data_ptr                   = event->data;

		jclass klass      = event->klass;
		char *class_name  = data_ptr;
		char *method_name = data_ptr + event->class_name_len + 1;
		char *method_sig =
		    data_ptr + event->class_name_len + 1 + event->method_name_len + 1;

		jmethodID mid = (*jni)->GetMethodID(jni, klass, method_name, method_sig);
		if (!mid)
		{
			(*jni)->ExceptionClear(jni);
			/* Not found for instance method, retry for static */
			mid = (*jni)->GetStaticMethodID(
			    jni, klass, method_name, method_sig);
			if (!mid)
			{
				(*jni)->ExceptionClear(jni);
				LOG_ERROR("GetMethodID failed for %s.%s%s",
				          class_name,
				          method_name,
				          method_sig);
				goto cleanup;
			}
		}

		LOG_DEBUG("Resolved mid %p for %s.%s", mid, class_name, method_name);

		if (event->type == METHOD_ENTRY)
		{
			LOG_DEBUG("Calling record_method_entry_event for %s.%s",
			          class_name,
			          method_name);
			record_method_entry_event(ctx, event, mid);
		}
		else
		{
			LOG_DEBUG("Calling record_method_exit_event for %s.%s",
			          class_name,
			          method_name);
			record_method_exit_event(ctx, event, mid);
		}

	cleanup:
		/* Note: klass is now a reference to a cached GlobalRef in
		   class_info_by_name, owned by the hashtable - do NOT delete it here */
		mpsc_ring_release(&ctx->method_ring, handle);
	}

	/* Detach from JVM */
	(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Method events thread exiting");
	return NULL;
}

void *
obj_alloc_event_thread_func(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;

	LOG_INFO("Object allocation event thread started");

	while (check_worker_status(ctx->tm_ctx.worker_statuses, OBJ_ALLOC_EVENTS_RUNNING))
	{
		uint32_t handle;
		if (mpsc_ring_consume(&ctx->obj_alloc_ring, &handle) != 0)
		{
			usleep(1000); /* 1ms sleep when empty */
			continue;
		}

		serialized_obj_alloc_event_t *event =
		    (serialized_obj_alloc_event_t *)mpsc_ring_get(&ctx->obj_alloc_ring,
		                                                  handle);

		if (event && event->obj_alloc_index >= 0)
		{

			ctx->object_metrics->allocation_counts[event->obj_alloc_index]++;
			ctx->object_metrics->total_bytes[event->obj_alloc_index] +=
			    event->sz;
			ctx->object_metrics->current_instances[event->obj_alloc_index]++;

			if (event->sz
			    < ctx->object_metrics->min_size[event->obj_alloc_index])
				ctx->object_metrics->min_size[event->obj_alloc_index] =
				    event->sz;

			if (event->sz
			    > ctx->object_metrics->max_size[event->obj_alloc_index])
				ctx->object_metrics->max_size[event->obj_alloc_index] =
				    event->sz;
		}

		mpsc_ring_release(&ctx->obj_alloc_ring, handle);
	}

	LOG_INFO("Object allocation event thread exiting");
	return NULL;
}