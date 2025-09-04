/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "cooper_ring.h"
#include "cooper_thread_workers.h"

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

	jvmtiPhase jvm_phase;
	if ((*jvmti_env)->GetPhase(jvmti_env, &jvm_phase) != JVMTI_ERROR_NONE
	    || jvm_phase != JVMTI_PHASE_LIVE)
	{
		LOG_ERROR("Cannot get the thread id as jvm is not in correct phase: %d",
		          jvm_phase);
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

	/* Use Thread.getId() as a key to our mapping table */
	pthread_mutex_lock(&ctx->samples_lock);

	/* Check for previous mapping */
	for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
	{
		if (ctx->thread_mappings[i].java_thread_id == thread_id)
		{
			result = ctx->thread_mappings[i].native_thread_id;
			LOG_DEBUG("Found existing mapping: Java ID %lld -> Native ID %d",
			          (long long)thread_id,
			          result);
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
		jvmtiError err =
		    (*jvmti_env)->GetCurrentThread(jvmti_env, &current_thread);
		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR("GetCurrentThread failed with error %d", err);
			return 0;
		}

		jboolean is_same_thread =
		    (*jni)->IsSameObject(jni, thread, current_thread);
		(*jni)->DeleteLocalRef(jni, current_thread);
		if (is_same_thread)
		{
			result = syscall(SYS_gettid);
			LOG_DEBUG("Current thread ID: %d for Java thread ID: %lld",
			          result,
			          (long long)thread_id);

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
				ctx->thread_mappings[empty_slot].java_thread_id =
				    thread_id;
				ctx->thread_mappings[empty_slot].native_thread_id =
				    result;
			}
			else
				LOG_ERROR("No empty slots available for thread mapping");

			pthread_mutex_unlock(&ctx->samples_lock);
		}
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
		fprintf(fp,
		        "%" PRIu64 ",%" PRIu64 "\n",
		        ctx->app_memory_metrics->timestamps[i],
		        ctx->app_memory_metrics->process_memory_sample[i]);
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
			fprintf(fp,
			        "%s,%lu,%lu,%lu,%lu,%lu,%lu\n",
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
			// if (ctx->metrics->sample_counts[i] > 0)
			// 	avg_time = ctx->metrics->total_time_ns[i]
			// 	           / ctx->metrics->sample_counts[i];

			total_calls += ctx->metrics->call_counts[i];
			// total_samples += ctx->metrics->sample_counts[i];

			/* Debug output to verify each method's metrics */
			LOG_DEBUG("Method[%zu]: %s, calls=%lu, samples=%lu, time=%lu\n",
			          i,
			          ctx->metrics->signatures[i],
			          (unsigned long)ctx->metrics->call_counts[i],
			          0,
			          //   (unsigned long)ctx->metrics->sample_counts[i],
			          (unsigned long)ctx->metrics->total_time_ns[i]);

			/* Print out the details */
			fprintf(fp,
			        "%s,%lu,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
			        ctx->metrics->signatures[i],
			        (unsigned long)ctx->metrics->call_counts[i],
			        0,
			        // (unsigned long)ctx->metrics->sample_counts[i],
			        (unsigned long)ctx->metrics->total_time_ns[i],
			        (unsigned long)avg_time,
			        (unsigned long)(ctx->metrics->min_time_ns[i] == UINT64_MAX
			                            ? 0
			                            : ctx->metrics->min_time_ns[i]),
			        (unsigned long)ctx->metrics->max_time_ns[i],
			        (unsigned long)ctx->metrics->alloc_bytes[i],
			        (unsigned long)ctx->metrics->peak_memory[i],
			        (unsigned long)ctx->metrics->cpu_cycles[i]);
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

	pthread_mutex_unlock(&ctx->samples_lock);

	fclose(fp);
}

static void
export_method_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->metrics)
		return;

	pthread_mutex_lock(&ctx->samples_lock);

	for (size_t i = 0; i < ctx->metrics->capacity; i++)
	{
		if (ctx->metrics->signatures[i])
		{
			/* Create clean method data structure */
			cooper_method_data_t method_data = {0};

			strncpy(method_data.signature,
			        ctx->metrics->signatures[i],
			        COOPER_MAX_SIGNATURE_LEN - 1);
			method_data.signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';

			/* Direct field assignment */
			method_data.call_count = ctx->metrics->call_counts[i];
			// method_data.sample_count  = ctx->metrics->sample_counts[i];
			method_data.total_time_ns = ctx->metrics->total_time_ns[i];
			method_data.min_time_ns   = ctx->metrics->min_time_ns[i];
			method_data.max_time_ns   = ctx->metrics->max_time_ns[i];
			method_data.alloc_bytes   = ctx->metrics->alloc_bytes[i];
			method_data.peak_memory   = ctx->metrics->peak_memory[i];
			method_data.cpu_cycles    = ctx->metrics->cpu_cycles[i];
			method_data.metric_flags  = ctx->metrics->metric_flags[i];

			cooper_shm_write_method_data(ctx->shm_ctx, &method_data);
		}
	}

	pthread_mutex_unlock(&ctx->samples_lock);
}

/**
 * Export memory samples to shared memory
 */
static void
export_memory_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->app_memory_metrics)
		return;

	pthread_mutex_lock(&ctx->app_memory_metrics->lock);

	/* Export latest process memory sample */
	if (ctx->app_memory_metrics->sample_count > 0)
	{
		size_t latest_idx =
		    (ctx->app_memory_metrics->sample_count - 1) % MAX_MEMORY_SAMPLES;

		/* Clean memory data structure */
		cooper_memory_data_t memory_data = {
		    .process_memory =
			ctx->app_memory_metrics->process_memory_sample[latest_idx],
		    .thread_id     = 0, /* Process-wide */
		    .thread_memory = 0};

		cooper_shm_write_memory_data(ctx->shm_ctx, &memory_data);
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

				cooper_memory_data_t memory_data = {
				    .process_memory =
					0, /* Not applicable for thread-specific */
				    .thread_id     = tm->thread_id,
				    .thread_memory = tm->memory_samples[latest_idx]};

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
static void
export_object_alloc_to_shm(agent_context_t *ctx)
{
	if (!ctx->shm_ctx || !ctx->object_metrics)
		return;

	pthread_mutex_lock(&ctx->samples_lock);

	for (size_t i = 0; i < ctx->object_metrics->count; i++)
	{
		if (ctx->object_metrics->class_signatures[i]
		    && ctx->object_metrics->allocation_counts[i] > 0)
		{

			/* Clean object allocation data */
			cooper_object_alloc_data_t alloc_data = {0};

			strncpy(alloc_data.class_signature,
			        ctx->object_metrics->class_signatures[i],
			        COOPER_MAX_SIGNATURE_LEN - 1);
			alloc_data.class_signature[COOPER_MAX_SIGNATURE_LEN - 1] = '\0';

			/* Semantic field names */
			alloc_data.allocation_count =
			    ctx->object_metrics->allocation_counts[i];
			alloc_data.current_instances =
			    ctx->object_metrics->current_instances[i];
			alloc_data.total_bytes = ctx->object_metrics->total_bytes[i];
			alloc_data.peak_instances =
			    ctx->object_metrics->peak_instances[i];
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
			arena_t *metrics_arena = ctx->arenas[METRICS_ARENA_ID];
			if (metrics_arena)
			{
				thread_metrics = arena_alloc(
				    metrics_arena, sizeof(thread_memory_metrics_t));
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
		}

		/* Store the memory sample */
		if (thread_metrics)
		{
			size_t idx = thread_metrics->sample_count % MAX_MEMORY_SAMPLES;
			thread_metrics->memory_samples[idx] = thread_mem;
			thread_metrics->timestamps[idx]     = timestamp;

			if (thread_metrics->sample_count < MAX_MEMORY_SAMPLES)
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

/* Improved hashtable sizing with better limits */
static size_t
calculate_hashtable_size(int class_count)
{
	/* Defensive bounds checking - check negative first */
	if (class_count <= 0)
	{
		LOG_WARN("Invalid class count (%d), using minimum hash size of %d",
		         class_count,
		         MIN_HASH_SIZE);
		return MIN_HASH_SIZE;
	}

	/* Now safe to cast to unsigned for overflow check */
	size_t class_count_unsigned = (size_t)class_count;

	/* Use load factor of 0.6 for better performance, with overflow protection */
	size_t estimated_size;
	if (class_count_unsigned > SIZE_MAX / 2)
	{
		LOG_WARN("Class count too large, capping hash table size to %d",
		         MAX_HASH_SIZE);
		estimated_size = MAX_HASH_SIZE;
	}
	else
		estimated_size =
		    (size_t)(class_count_unsigned * 1.7); /* Account for heap growth */

	if (estimated_size < MIN_HASH_SIZE)
	{
		estimated_size = MIN_HASH_SIZE;
	}
	else if (estimated_size > MAX_HASH_SIZE)
	{
		LOG_WARN("Capping hash table size from %zu to %zu for safety",
		         estimated_size,
		         MAX_HASH_SIZE);
		estimated_size = MAX_HASH_SIZE;
	}

	LOG_DEBUG("Calculated hash table size: %zu for %d classes",
	          estimated_size,
	          class_count_unsigned);
	return estimated_size;
}

/* Fully robust heap statistics collection maintaining all safety checks */
static void
collect_heap_statistics(agent_context_t *ctx, JNIEnv *env)
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
	min_heap_t *heap = min_heap_create(scratch_arena, TOP_N, class_stats_compare);
	if (!heap)
	{
		LOG_ERROR("Failed to create min heap");
		goto cleanup_classes;
	}

	/* Create generic hashtable for class statistics */
	size_t hash_size      = calculate_hashtable_size(class_count);
	hashtable_t *class_ht = ht_create(scratch_arena, hash_size, 0.75);
	if (!class_ht)
	{
		LOG_ERROR("Failed to create class generic hashtable");
		goto cleanup_classes;
	}

	/* Set up iteration context with validation */
	heap_iteration_context_t iter_ctx = {
	    .env = env, .jvmti = jvmti, .arena = scratch_arena, .class_table = class_ht};

	/* Validate context before proceeding */
	if (!iter_ctx.env || !iter_ctx.jvmti || !iter_ctx.arena || !iter_ctx.class_table)
	{
		LOG_ERROR("Invalid iteration context");
		goto cleanup_classes;
	}

	/* Tag classes for heap iteration */
	for (int i = 0; i < class_count; i++)
	{
		jlong tag = 0;
		(*jvmti)->GetTag(jvmti, classes[i], &tag);

		if (tag != 0)
		{
			class_info_t *info      = (class_info_t *)(intptr_t)tag;
			info->in_heap_iteration = 1;
		}
	}

	/* Use centralized heap callbacks */
	LOG_INFO("Starting heap iteration (hashtable size: %zu)", hash_size);
	err = (*jvmti)->FollowReferences(
	    jvmti, 0, NULL, NULL, &ctx->callbacks.heap_callbacks, &iter_ctx);
	if (err != JVMTI_ERROR_NONE)
	{
		LOG_ERROR("Heap iteration failed: %d", err);
		goto cleanup_tags;
	}
	LOG_INFO("Heap iteration completed, processing %zu unique classes",
	         iter_ctx.class_table->count);

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

		/* Only resolve names for potential top-N entries */
		if (heap->size < TOP_N
		    || stats->total_size
		           > ((class_stats_t *)heap->elements[0])->total_size)
		{
			class_stats_t *heap_entry =
			    arena_alloc(scratch_arena, sizeof(class_stats_t));
			if (!heap_entry)
			{
				LOG_WARN("Failed to allocate heap entry %zu", i);
				continue;
			}

			/* Copy stats */
			*heap_entry            = *stats;
			heap_entry->class_name = arena_strdup(scratch_arena, entry->key);

			if (!heap_entry->class_name)
			{
				/* Without a class name nothing to do */
				arena_free(scratch_arena, heap_entry);
				continue;
			}

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
			class_info_t *info      = (class_info_t *)(intptr_t)tag;
			info->in_heap_iteration = 0;
		}
	}

cleanup_classes:
	(*jvmti)->Deallocate(jvmti, (unsigned char *)classes);
}

/**
 * Finds the index for a method in the metrics array based on filter rules.
 * This is a read-only, non-locking function used during class loading.
 *
 * @return The index into the metrics array if a match is found, otherwise -1.
 */
static int
find_method_filter_index(agent_context_t *ctx,
                         const char *class_signature,
                         const char *method_name,
                         const char *method_signature)
{
	char full_sig[MAX_SIG_SZ];

	/* Check for an exact match first */
	snprintf(full_sig,
	         sizeof(full_sig),
	         "%s %s %s",
	         class_signature,
	         method_name,
	         method_signature);
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
static void
cache_class_info(agent_context_t *ctx, arena_t *arena, jvmtiEnv *jvmti_env, jclass klass)
{
	assert(jvmti_env != NULL);

	static int cache_call_count = 0;
	cache_call_count++;

	char *class_sig = NULL;
	jvmtiError err =
	    (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);

	if (err != JVMTI_ERROR_NONE || class_sig == NULL)
		goto deallocate;

	/* Get all methods for the class */
	jint method_count  = 0;
	jmethodID *methods = NULL;
	err = (*jvmti_env)->GetClassMethods(jvmti_env, klass, &method_count, &methods);

	if (err != JVMTI_ERROR_NONE)
		goto deallocate;

	/* We only care about classes with methods */
	if (method_count == 0)
		goto deallocate;

	/* Allocate the main class_info struct from the class cache arena */
	class_info_t *info = arena_alloc(arena, sizeof(class_info_t));
	if (info == NULL)
		goto deallocate;

	strncpy(info->class_sig, class_sig, sizeof(info->class_sig) - 1);
	info->in_heap_iteration = 0;

	/* Allocate space for the method info array in the same arena */
	info->methods      = arena_alloc(arena, sizeof(method_info_t) * method_count);
	info->method_count = method_count;

	/* If we are unable to allocate mem for methods,
	free the class_info mem and stop processing this class */
	if (!info->methods)
	{
		arena_free(arena, info);
		goto deallocate;
	}

	/* Loop through each method and cache its details */
	for (int i = 0; i < method_count; i++)
	{
		char *method_name          = NULL;
		char *method_sig           = NULL;
		info->methods[i].method_id = methods[i];

		/* Skip any method where we cannot get name */
		if ((*jvmti_env)
		        ->GetMethodName(
			    jvmti_env, methods[i], &method_name, &method_sig, NULL)
		    != JVMTI_ERROR_NONE)
			continue;

		/* Store arena-allocated copies of the names */
		info->methods[i].method_name      = arena_strdup(arena, method_name);
		info->methods[i].method_signature = arena_strdup(arena, method_sig);

		info->methods[i].sample_index =
		    find_method_filter_index(ctx, class_sig, method_name, method_sig);

		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_name);
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_sig);
	}

	/* Set the tag */
	jlong tag = (jlong)(intptr_t)info;
	err       = (*jvmti_env)->SetTag(jvmti_env, klass, tag);
	if (err != JVMTI_ERROR_NONE)
		LOG_ERROR("Failed to set tag for class %s, error: %d", class_sig, err);

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
	while (check_worker_status(ctx->worker_statuses, EXPORT_RUNNING))
	{
		/* Sleep in smaller increments to be more responsive to shutdown */
		for (int i = 0;
		     i < ctx->config.export_interval
		     && check_worker_status(ctx->worker_statuses, EXPORT_RUNNING);
		     i++)
			sleep(1);

		if (check_worker_status(ctx->worker_statuses, EXPORT_RUNNING))
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
	while (check_worker_status(ctx->worker_statuses, SHM_EXPORT_RUNNING))
	{
		if (ctx->shm_ctx == NULL)
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
	jvmtiError err;
	jvmtiPhase jvm_phase;

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

	while (check_worker_status(ctx->worker_statuses, MEM_SAMPLING_RUNNING))
	{
		err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR("Error getting the current jvm phase - maybe during "
			          "shutdown? error %d",
			          err);
			return NULL;
		}

		if (jvm_phase != JVMTI_PHASE_LIVE)
		{
			LOG_INFO("JVM is not in live phase, cannot sample thread memory, "
			         "current jvm phase: %d",
			         jvm_phase);
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
			size_t idx =
			    ctx->app_memory_metrics->sample_count % MAX_MEMORY_SAMPLES;
			ctx->app_memory_metrics->process_memory_sample[idx] = process_mem;
			ctx->app_memory_metrics->timestamps[idx]            = timestamp;

			if (ctx->app_memory_metrics->sample_count < MAX_MEMORY_SAMPLES)
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

	/* We cannot detach thread if the jvmPhase is not JVMTI_PHASE_LIVE */
	err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
	if (err == JVMTI_ERROR_NONE && jvm_phase == JVMTI_PHASE_LIVE)
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
	jvmtiError err;
	jvmtiPhase jvm_phase;

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
	while (check_worker_status(ctx->worker_statuses, HEAP_STATS_RUNNING))
	{
		err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR("Error getting JVM phase in heap stats thread: %d",
			          err);
			// goto cleanup;
			sleep(10);
			continue;
		}

		if (jvm_phase != JVMTI_PHASE_LIVE)
		{
			LOG_INFO(
			    "JVM not in live phase, skipping heap statistics collection");
			sleep(10);
			continue;
		}

		/* Collect heap statistics */
		collect_heap_statistics(ctx, jni);

		/* Sleep for 60 seconds between collections */
		sleep(60);
	}

	/* Detach from JVM if JVM is still live */
	err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
	if (err == JVMTI_ERROR_NONE && jvm_phase == JVMTI_PHASE_LIVE)
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
	q_t *queue           = ctx->class_queue;
	arena_t *arena       = ctx->arenas[CLASS_CACHE_ARENA_ID];

	/* Get JNI environment for this thread */
	JNIEnv *jni = NULL;
	jvmtiError err;
	jvmtiPhase jvm_phase;

	jint res =
	    (*ctx->jvm)->AttachCurrentThreadAsDaemon(ctx->jvm, (void **)&jni, NULL);
	if (res != JNI_OK || jni == NULL)
	{
		LOG_ERROR("Failed to attach class cache thread to JVM");
		return NULL;
	}

	int classes_processed = 0;
	LOG_INFO("Class cache thread started, queue has %d entries", queue->count);

	while (check_worker_status(ctx->worker_statuses, CLASS_CACHE_RUNNING))
	{
		LOG_DEBUG("Waiting for class from queue...");
		q_entry_t *entry = q_deq(queue);

		/* Q shutdown or error */
		if (entry == NULL)
			break;

		if (entry->type != Q_ENTRY_CLASS)
		{
			LOG_ERROR("Queue entry type: %d, not a class entry type in class "
			          "queue!!",
			          entry->type);
			break;
		}

		class_q_entry_t *class_entry = (class_q_entry_t *)entry->data;

		classes_processed++;
		LOG_DEBUG("Processing class #%d from queue", classes_processed);
		cache_class_info(ctx, arena, ctx->jvmti_env, class_entry->klass);

		/* Delete the global reference after processing
		class_entry->klass is a global ref assigned in precache_loaded_classes or
		class_load_callback
		*/
		(*jni)->DeleteGlobalRef(jni, class_entry->klass);
	}

	/* Detach from JVM */
	err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
	if (err == JVMTI_ERROR_NONE && jvm_phase == JVMTI_PHASE_LIVE)
		(*ctx->jvm)->DetachCurrentThread(ctx->jvm);

	LOG_INFO("Class cache thread exiting, processed %d classes", classes_processed);
	return NULL;
}

// TODO adjust this to use a ringbuffer when ready.
/**
 *
 */
void *
call_stack_sampling_thread_func(void *arg)
{
	agent_context_t *ctx = (agent_context_t *)arg;
	jvmtiEnv *jvmti      = ctx->jvmti_env;
	jvmtiPhase jvm_phase;
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

	arena_t *arena = ctx->arenas[CALL_STACK_ARENA_ID];
	if (!arena)
	{
		LOG_ERROR("Call stack arena is not initialised");
		return NULL;
	}

	while (check_worker_status(ctx->worker_statuses, CALL_STACK_RUNNNG))
	{
		err = (*ctx->jvmti_env)->GetPhase(ctx->jvmti_env, &jvm_phase);
		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR(
			    "Error getting JVM phase in call stack sampling thread: %d",
			    err);
			sleep(10);
			continue;
		}

		if (jvm_phase != JVMTI_PHASE_LIVE)
		{
			LOG_INFO("JVM not in live phase, skipping call stack sampling");
			sleep(10);
			continue;
		}

		// sleep for configured interval
		// usleep(ctx->config.stack_sample_interval * 1000); // e.g. 10ms
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
				jclass declaring_class;
				(*jvmti)->GetMethodDeclaringClass(
				    jvmti, mid, &declaring_class);

				jlong tag;
				(*jvmti)->GetTag(jvmti, declaring_class, &tag);
				if (tag == 0)
					continue;

				class_info_t *info = (class_info_t *)(intptr_t)tag;

				/* linear search */
				for (uint32_t m = 0; m < info->method_count; m++)
				{
					if (info->methods[m].method_id == mid
					    && info->methods[m].sample_index >= 0)
					{
						__atomic_add_fetch(
						    &ctx->metrics->call_sample_counts
							 [info->methods[m].sample_index],
						    1,
						    __ATOMIC_RELAXED);
					}
				}
			}

			/* Publish to channel ready ring */
			sample_publish(&ctx->call_stack_channel, idx);
		}

		(*jvmti)->Deallocate(jvmti, (unsigned char *)threads);
	}

	return NULL;
}
