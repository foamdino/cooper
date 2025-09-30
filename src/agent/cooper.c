/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "cooper_thread_manager.h"

static agent_context_t *global_ctx = NULL; /* Single global context */

/* Thread-local storage key and initialization mutex */
static pthread_key_t context_key;
static pthread_once_t tls_init_once = PTHREAD_ONCE_INIT;

/* Arena configurations */
/* clang-format off */
static const arena_config_t arena_configs[] = 
{
    {EXCEPTION_ARENA_ID, EXCEPTION_ARENA_NAME, EXCEPTION_ARENA_SZ, EXCEPTION_ARENA_BLOCKS},
    {LOG_ARENA_ID, LOG_ARENA_NAME, LOG_ARENA_SZ, LOG_ARENA_BLOCKS},
    {SAMPLE_ARENA_ID, SAMPLE_ARENA_NAME, SAMPLE_ARENA_SZ, SAMPLE_ARENA_BLOCKS},
    {CONFIG_ARENA_ID, CONFIG_ARENA_NAME, CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS},
    {METRICS_ARENA_ID, METRICS_ARENA_NAME, METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS},
    {SCRATCH_ARENA_ID, SCRATCH_ARENA_NAME, SCRATCH_ARENA_SZ, SCRATCH_ARENA_BLOCKS},
    {CLASS_CACHE_ARENA_ID, CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS},
    {Q_ENTRY_ARENA_ID, Q_ENTRY_ARENA_NAME, Q_ENTRY_ARENA_SZ, Q_ENTRY_ARENA_BLOCKS},
	{CALL_STACK_ARENA_ID, CALL_STACK_ARENA_NAME, CALL_STACK_ARENA_SZ, CALL_STACK_ARENA_BLOCKS},
	{FLAMEGRAPH_ARENA_ID, FLAMEGRAPH_ARENA_NAME, FLAMEGRAPH_ARENA_SZ, FLAMEGRAPH_ARENA_BLOCKS},
	{METHOD_CACHE_ARENA_ID, METHOD_CACHE_ARENA_NAME, METHOD_CACHE_ARENA_SZ, METHOD_CACHE_ARENA_BLOCKS},
	{BYTECODE_ARENA_ID, BYTECODE_ARENA_NAME, BYTECODE_ARENA_SZ, BYTECODE_ARENA_BLOCKS}
};

/* Output from xxd -i */
static const signed char TRACKER_CLASS_BYTECODE[] =
{
  0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x44, 0x00, 0x10, 0x0a, 0x00,
  0x02, 0x00, 0x03, 0x07, 0x00, 0x04, 0x0c, 0x00, 0x05, 0x00, 0x06, 0x01,
  0x00, 0x10, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f,
  0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x01, 0x00, 0x06, 0x3c, 0x69, 0x6e,
  0x69, 0x74, 0x3e, 0x01, 0x00, 0x03, 0x28, 0x29, 0x56, 0x07, 0x00, 0x08,
  0x01, 0x00, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75,
  0x62, 0x2f, 0x66, 0x6f, 0x61, 0x6d, 0x64, 0x69, 0x6e, 0x6f, 0x2f, 0x63,
  0x6f, 0x6f, 0x70, 0x65, 0x72, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2f,
  0x4e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x65,
  0x72, 0x01, 0x00, 0x04, 0x43, 0x6f, 0x64, 0x65, 0x01, 0x00, 0x0f, 0x4c,
  0x69, 0x6e, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x54, 0x61, 0x62,
  0x6c, 0x65, 0x01, 0x00, 0x0d, 0x6f, 0x6e, 0x4d, 0x65, 0x74, 0x68, 0x6f,
  0x64, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x01, 0x00, 0x39, 0x28, 0x4c, 0x6a,
  0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72,
  0x69, 0x6e, 0x67, 0x3b, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61,
  0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x3b, 0x4c, 0x6a,
  0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x53, 0x74, 0x72,
  0x69, 0x6e, 0x67, 0x3b, 0x29, 0x56, 0x01, 0x00, 0x0c, 0x6f, 0x6e, 0x4d,
  0x65, 0x74, 0x68, 0x6f, 0x64, 0x45, 0x78, 0x69, 0x74, 0x01, 0x00, 0x0a,
  0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x46, 0x69, 0x6c, 0x65, 0x01, 0x00,
  0x12, 0x4e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x54, 0x72, 0x61, 0x63, 0x6b,
  0x65, 0x72, 0x2e, 0x6a, 0x61, 0x76, 0x61, 0x00, 0x21, 0x00, 0x07, 0x00,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0x00,
  0x06, 0x00, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x01, 0x00,
  0x01, 0x00, 0x00, 0x00, 0x05, 0x2a, 0xb7, 0x00, 0x01, 0xb1, 0x00, 0x00,
  0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x03, 0x01, 0x09, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x09,
  0x00, 0x0d, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x0f
};
/* clang-format on */

static const char *TRACKER_CLASS = "com/github/foamdino/cooper/agent/NativeTracker";

/* Get current time in nanoseconds */
uint64_t
get_current_time_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#ifdef ENABLE_DEBUG_LOGS
/* Debug function for dumping method stack */
static void
debug_dump_method_stack(agent_context_t *ctx, thread_context_t *tc)
{
	if (!ctx || !tc)
		return;

	LOG_DEBUG("Method stack dump (depth=%d):\n", tc->stack_depth);

	method_sample_t *current = tc->sample;
	int level                = 0;

	while (current && level < 20) /* Have a depth cutoff */
	{
		/* Get method details */
		char *method_name = NULL;
		char *method_sig  = NULL;

		jvmtiError err = (*ctx->jvmti_env)
		                     ->GetMethodName(ctx->jvmti_env,
		                                     current->method_id,
		                                     &method_name,
		                                     &method_sig,
		                                     NULL);
		if (err == JVMTI_ERROR_NONE)
		{
			LOG_DEBUG("\t[%d] methodID=%p, index=%d, name=%s%s\n",
			          level,
			          current->method_id,
			          current->method_index,
			          method_name,
			          method_sig);

			(*ctx->jvmti_env)
			    ->Deallocate(ctx->jvmti_env, (unsigned char *)method_name);
			(*ctx->jvmti_env)
			    ->Deallocate(ctx->jvmti_env, (unsigned char *)method_sig);
		}
		else
			LOG_DEBUG("\t[%d] methodID=%p, index=%d, <name-error>\n",
			          level,
			          current->method_id,
			          current->method_index);

		current = current->parent;
		level++;
	}
}
#endif

static void
destroy_thread_context(void *data)
{
	thread_context_t *tc = (thread_context_t *)data;

	/* We can ignore cleaning up the method_samples
	as they are arena allocated*/
	if (tc)
	{
		tc->sample      = NULL;
		tc->stack_depth = 0;
		free(tc);
	}
}

static void
init_thread_local_storage_once(void)
{
	pthread_key_create(&context_key, destroy_thread_context);
}

/* Initialize thread-local storage */
static void
init_thread_local_storage()
{
	pthread_once(&tls_init_once, init_thread_local_storage_once);
}

/* Get the thread-local sample structure */
thread_context_t *
get_thread_local_context()
{
	init_thread_local_storage();

	thread_context_t *context = pthread_getspecific(context_key);
	if (!context)
	{
		/* First time this thread is accessing the key */
		context = calloc(1, sizeof(thread_context_t));
		if (context)
		{
			context->sample      = NULL;
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
static int
get_cached_class_signature(jvmtiEnv *jvmti_env, jclass klass, char **output_buffer)
{
	if (!output_buffer || !jvmti_env || !klass)
		return COOPER_ERR;

	jlong tag      = 0;
	jvmtiError err = (*jvmti_env)->GetTag(jvmti_env, klass, &tag);
	if (err != JVMTI_ERROR_NONE)
		return COOPER_ERR;

	/* If we don't have a tag, there's nothing we can do here */
	if (tag == 0)
		return COOPER_ERR;

	cooper_class_info_t *info = (cooper_class_info_t *)(intptr_t)tag;
	*output_buffer            = info->class_sig;
	return COOPER_OK;
}

/**
 * Initialise a method_sample_t structure
 *
 * Return NULL if it fails to allocate space in the provided arena
 */
method_sample_t *
init_method_sample(arena_t *arena,
                   int method_index,
                   jmethodID method_id,
                   uint64_t timestamp,
                   uint64_t cpu)
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
	sample->method_id    = method_id;
	/* current_alloc_bytes and parent already zero-initialized by arena_alloc */

	unsigned int flags = global_ctx->metrics->metric_flags[method_index];

	if (flags & METRIC_FLAG_TIME)
		sample->start_time = timestamp;

	if (flags & METRIC_FLAG_CPU)
		sample->start_cpu = cpu;

	return sample;
}

/* Record method execution metrics */
void
record_method_execution(agent_context_t *ctx,
                        int method_index,
                        uint64_t exec_time_ns,
                        uint64_t memory_bytes,
                        uint64_t cycles)
{
	method_metrics_soa_t *metrics = ctx->metrics;

	/* Check for valid index */
	if (method_index < 0 || (size_t)method_index >= metrics->count)
	{
		LOG_WARN("WARNING: method_index: %d not found in soa struct\n",
		         method_index);
		return;
	}

	// /* Update sample count */
	// atomic_fetch_add_explicit(&metrics->sample_counts[method_index], 1,
	// memory_order_relaxed);

	/* Update timing metrics if enabled */
	if ((metrics->metric_flags[method_index] & METRIC_FLAG_TIME) != 0)
	{
		atomic_fetch_add_explicit(&metrics->total_time_ns[method_index],
		                          exec_time_ns,
		                          memory_order_relaxed);

		/* Update min/max */
		pthread_mutex_lock(&ctx->tm_ctx.samples_lock);

		if (exec_time_ns < metrics->min_time_ns[method_index])
			metrics->min_time_ns[method_index] = exec_time_ns;

		if (exec_time_ns > metrics->max_time_ns[method_index])
			metrics->max_time_ns[method_index] = exec_time_ns;

		pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);
	}

	/* Update memory metrics if enabled */
	if ((metrics->metric_flags[method_index] & METRIC_FLAG_MEMORY) != 0)
	{
		atomic_fetch_add_explicit(&metrics->alloc_bytes[method_index],
		                          memory_bytes,
		                          memory_order_relaxed);

		pthread_mutex_lock(&ctx->tm_ctx.samples_lock);

		if (memory_bytes > metrics->peak_memory[method_index])
			metrics->peak_memory[method_index] = memory_bytes;

		pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);
	}

	/* Update CPU metrics if enabled */
	if ((metrics->metric_flags[method_index] & METRIC_FLAG_CPU) != 0)
		atomic_fetch_add_explicit(
		    &metrics->cpu_cycles[method_index], cycles, memory_order_relaxed);
}

static object_allocation_metrics_t *
init_object_allocation_metrics(arena_t *arena, size_t initial_capacity)
{

	assert(arena != NULL);

	object_allocation_metrics_t *metrics = arena_alloc_aligned(
	    arena, sizeof(object_allocation_metrics_t), CACHE_LINE_SZ);
	if (!metrics)
		return NULL;

	metrics->capacity = initial_capacity;

	/* Allocate arrays in SoA structure */
	metrics->class_signatures =
	    arena_alloc_aligned(arena, initial_capacity * sizeof(char *), CACHE_LINE_SZ);
	metrics->allocation_counts = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->total_bytes = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->peak_instances = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->current_instances = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->min_size = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->max_size = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->avg_size = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);

	if (!metrics->class_signatures || !metrics->allocation_counts
	    || !metrics->total_bytes || !metrics->peak_instances
	    || !metrics->current_instances || !metrics->min_size || !metrics->max_size
	    || !metrics->avg_size)
		return NULL;

	/* Set min_size to maximum value initially */
	for (size_t i = 0; i < initial_capacity; i++)
		metrics->min_size[i] = UINT64_MAX;

	return metrics;
}

/**
 *
 * @return position in array of object allocation stats or -1 on failure
 */
static int
find_or_add_object_type(object_allocation_metrics_t *obj_metrics, const char *class_sig)
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
			LOG_ERROR("class_signatures[%d] is NULL when count=%zu\n",
			          i,
			          obj_metrics->count);
			return -1;
		}
	}

	/* Do we have space to add new allocation stats? */
	if (obj_metrics->count >= obj_metrics->capacity)
	{
		LOG_WARN("Object metrics capacity reached (%zu)\n",
		         obj_metrics->capacity);
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
		LOG_ERROR("Failed to allocate memory for class signature: %s\n",
		          class_sig);
		return -1;
	}

	/* Only set non-zero values, the rest of the values are initialised to 0 */
	obj_metrics->min_size[index] = UINT64_MAX;
	obj_metrics->count++;
	LOG_DEBUG("Added object type at index %d: %s (total types: %zu)\n",
	          index,
	          class_sig,
	          obj_metrics->count);
	return index;
}

static void
update_object_allocation_stats(agent_context_t *ctx,
                               const char *class_sig,
                               uint64_t safe_sz)
{
	assert(ctx != NULL);
	assert(class_sig != NULL);

	if (!ctx || !class_sig)
		return;

	int index = find_or_add_object_type(ctx->object_metrics, class_sig);
	if (index >= 0)
	{
		atomic_fetch_add_explicit(&ctx->object_metrics->allocation_counts[index],
		                          1,
		                          memory_order_relaxed);
		atomic_fetch_add_explicit(&ctx->object_metrics->total_bytes[index],
		                          safe_sz,
		                          memory_order_relaxed);
		atomic_fetch_add_explicit(&ctx->object_metrics->current_instances[index],
		                          1,
		                          memory_order_relaxed);

		// TODO need different locks / stats instead of using single lock
		/* Update size statistics */
		pthread_mutex_lock(&ctx->tm_ctx.samples_lock);
		if (safe_sz < ctx->object_metrics->min_size[index])
			ctx->object_metrics->min_size[index] = safe_sz;

		if (safe_sz > ctx->object_metrics->max_size[index])
			ctx->object_metrics->max_size[index] = safe_sz;

		/* Update average size */
		ctx->object_metrics->avg_size[index] =
		    ctx->object_metrics->total_bytes[index]
		    / ctx->object_metrics->allocation_counts[index];
		pthread_mutex_unlock(&ctx->tm_ctx.samples_lock);
	}
}

#ifdef ENABLE_DEBUG_LOGS
/**
 * get a param value for a method
 *
 */
static char *
get_parameter_value(arena_t *arena,
                    jvmtiEnv *jvmti,
                    JNIEnv *jni_env,
                    jthread thread,
                    jint param_slot,
                    char param_type)
{
	char *result = NULL;
	jvalue value;
	jvmtiError err;

	switch (param_type)
	{
		/* int */
		case 'I':
			err =
			    (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
			if (err == JVMTI_ERROR_NONE)
			{
				/* Allocate space for result (max int digist + sign +
				 * null) */
				result = arena_alloc(arena, 12);
				if (result)
					sprintf(result, "%d", value.i);
			}
			break;

		/* long */
		case 'J':
			err = (*jvmti)->GetLocalLong(
			    jvmti, thread, 0, param_slot, &value.j);
			if (err == JVMTI_ERROR_NONE)
			{
				result = arena_alloc(arena, 21);
				if (result)
					sprintf(result, "%lld", (long long)value.j);
			}
			break;

		/* float */
		case 'F':
			err = (*jvmti)->GetLocalFloat(
			    jvmti, thread, 0, param_slot, &value.f);
			if (err == JVMTI_ERROR_NONE)
			{
				result = arena_alloc(arena, 32);
				if (result)
					sprintf(result, "%f", value.f);
			}
			break;

		/* double */
		case 'D':
			err = (*jvmti)->GetLocalDouble(
			    jvmti, thread, 0, param_slot, &value.d);
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
			err =
			    (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
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
			err =
			    (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
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
			err =
			    (*jvmti)->GetLocalObject(jvmti, thread, 0, param_slot, &obj);
			if (err == JVMTI_ERROR_NONE && obj != NULL)
			{
				jstring str;
				jclass str_class =
				    (*jni_env)->FindClass(jni_env, "java/lang/String");
				/* We have a string */
				if ((*jni_env)->IsInstanceOf(jni_env, obj, str_class))
				{
					const char *str_value =
					    (*jni_env)->GetStringUTFChars(
						jni_env, obj, NULL);
					if (str_value)
					{
						result = arena_alloc(
						    arena,
						    strlen(str_value)
							+ 3); /* includes quotes and null
						               */
						if (result)
							sprintf(
							    result, "\"%s\"", str_value);

						(*jni_env)->ReleaseStringUTFChars(
						    jni_env, obj, str_value);
					}
				}
				else /* Non-string object */
				{
					jclass obj_class =
					    (*jni_env)->GetObjectClass(jni_env, obj);
					jmethodID toString_method =
					    (*jni_env)->GetMethodID(
						jni_env,
						obj_class,
						"toString",
						"()Ljava/lang/String;");
					str = (jstring)(*jni_env)->CallObjectMethod(
					    jni_env, obj, toString_method);

					if (str != NULL)
					{
						const char *str_value =
						    (*jni_env)->GetStringUTFChars(
							jni_env, str, NULL);
						if (str_value)
						{
							result = arena_alloc(
							    arena, strlen(str_value) + 1);
							if (result)
								strcpy(result, str_value);

							(*jni_env)->ReleaseStringUTFChars(
							    jni_env, str, str_value);
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
int
find_method_index(method_metrics_soa_t *metrics, const char *signature)
{
	if (!metrics || !signature)
		return -1;

	for (size_t i = 0; i < metrics->count; i++)
	{
		if (metrics->signatures[i]
		    && strcmp(metrics->signatures[i], signature) == 0)
			return (int)i;
	}

	return -1; /* Not found */
}

/**
 * Exception callback
 */
void JNICALL
exception_callback(jvmtiEnv *jvmti_env,
                   JNIEnv *jni_env,
                   jthread thread,
                   jmethodID method,
                   jlocation location,
                   jobject exception,
                   jmethodID catch_method,
                   jlocation catch_location)
{
	UNUSED(jvmti_env);
	UNUSED(jni_env);
	UNUSED(thread);
	UNUSED(method);
	UNUSED(location);
	UNUSED(exception);
	UNUSED(catch_method);
	UNUSED(catch_location);

	/* TODO do something more useful with exception callbacks - just logging at the
	 * moment is noise */
#ifdef ENABLE_DEBUG_LOGS
	return;
	UNUSED(location);
	UNUSED(catch_location);

	char *method_name      = NULL;
	char *method_signature = NULL;

	/* TODO is this needed? */
	char *generic_signature = NULL;

	char *class_name               = NULL;
	char *catch_method_name        = NULL;
	char *catch_method_signature   = NULL;
	jvmtiLocalVariableEntry *table = NULL;

	/* Get details of method */
	jvmtiError err = (*jvmti_env)
	                     ->GetMethodName(jvmti_env,
	                                     method,
	                                     &method_name,
	                                     &method_signature,
	                                     &generic_signature);

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
	jmethodID toString_id  = (*jni_env)->GetMethodID(
            jni_env, exception_class, "toString", "()Ljava/lang/String;");
	jstring exception_str =
	    (*jni_env)->CallObjectMethod(jni_env, exception, toString_id);
	if ((*jni_env)->ExceptionCheck(jni_env))
	{
		LOG_ERROR("JNI exception occurred while getting exception string\n");
		(*jni_env)->ExceptionClear(jni_env);
		goto deallocate;
	}

	/* Convert to standard C string */
	const char *exception_cstr =
	    exception_str ? (*jni_env)->GetStringUTFChars(jni_env, exception_str, NULL)
			  : "Unknown exception";

	LOG_DEBUG("Exception in %s.%s%s at location %ld\n",
	          class_name,
	          method_name,
	          method_signature,
	          (long)location);
	LOG_DEBUG("Exception details: %s\n", exception_cstr);

	/* Get the local variable table for this method */
	jint entry_count = 0;
	err =
	    (*jvmti_env)->GetLocalVariableTable(jvmti_env, method, &entry_count, &table);

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
			char param_type  = *params;
			char buffer[256] = {0};

			/* Handle obj types (find the end of the class name) */
			if (param_type == 'L')
			{
				strncpy(buffer, params, sizeof(buffer) - 1);
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
			char *param_val = get_parameter_value(
			    arena, jvmti_env, jni_env, thread, slot, param_type);

			LOG_DEBUG("\tParam %d (%s): %s\n",
			          param_idx,
			          param_name ? param_name : "<unknown>",
			          param_val ? param_val : "<error>");

			if (param_val)
				arena_free(arena, param_val);

			slot++;
			param_idx++;

			/* For long and double values they require two slots so advance a
			 * second time */
			if (param_type == 'J' || param_type == 'D')
				slot++;

			/* Next param */
			params++;
		}
	}

	/* Free the local variable table */
	for (int i = 0; i < entry_count; i++)
	{
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)table[i].name);
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)table[i].signature);
		(*jvmti_env)
		    ->Deallocate(jvmti_env, (unsigned char *)table[i].generic_signature);
	}

	/* Only try to deallocate with a valid pointer */
	if (table)
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)table);

	/* check the catch method */
	if (catch_method != NULL)
	{

		err = (*jvmti_env)
		          ->GetMethodName(jvmti_env,
		                          catch_method,
		                          &catch_method_name,
		                          &catch_method_signature,
		                          NULL);

		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR("GetMethodName for catch_method failed with error %d\n",
			          err);
			goto deallocate;
		}

		LOG_DEBUG("Caught in method: %s%s at location %ld\n",
		          catch_method_name,
		          catch_method_signature,
		          (long)catch_location);
	}

	/* Free exception_str */
	(*jni_env)->ReleaseStringUTFChars(jni_env, exception_str, exception_cstr);

deallocate:
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_name);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)method_signature);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)generic_signature);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)class_name);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)catch_method_name);
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)catch_method_signature);
#endif
}

static void JNICALL
object_alloc_callback(jvmtiEnv *jvmti_env,
                      JNIEnv *jni,
                      jthread thread,
                      jobject object,
                      jclass klass,
                      jlong size)
{
	UNUSED(jni);
	UNUSED(thread);
	UNUSED(object);

	/* Buffer for class signature */
	char *class_sig = NULL;

	/* Get cached class signature */
	if (get_cached_class_signature(jvmti_env, klass, &class_sig) != COOPER_OK)
		return;

	/* Convert the jlong (signed) to a uint64_t as we store our stats unsigned */
	uint64_t safe_sz = (size >= 0) ? (uint64_t)size : 0;

	/* Update the global allocation stats */
	update_object_allocation_stats(global_ctx, class_sig, safe_sz);

	/* Get thread-local context to prevent re-entrancy */
	thread_context_t *context = get_thread_local_context();
	if (!context)
		return;

	method_sample_t *sample = context->sample;
	if (!sample)
		return;

	/* Check if memory metrics are enabled for this method */
	if (sample->method_index < 0
	    || (size_t)sample->method_index >= global_ctx->metrics->count
	    || !(global_ctx->metrics->metric_flags[sample->method_index]
	         & METRIC_FLAG_MEMORY))
		return;

	/* Add allocation to the current method being sampled */
	sample->current_alloc_bytes += safe_sz;

	LOG_DEBUG("Allocation: %lld bytes for method_index %d, total: %lld, allocated "
	          "object of class: %s, size: %lld",
	          safe_sz,
	          sample->method_index,
	          (long long)sample->current_alloc_bytes,
	          class_sig,
	          safe_sz);
}

/* Check if a full method signature matches any filter */
pattern_filter_entry_t *
find_matching_filter(const pattern_filter_t *filter,
                     const char *class_sig,
                     const char *method_name,
                     const char *method_sig)
{
	assert(filter != NULL);
	assert(class_sig != NULL);
	assert(method_name != NULL);
	assert(method_sig != NULL);

	for (size_t i = 0; i < filter->num_entries; i++)
	{
		pattern_filter_entry_t *entry = &filter->entries[i];

		if (config_pattern_match(entry->class_pattern, class_sig)
		    && config_pattern_match(entry->method_pattern, method_name)
		    && config_pattern_match(entry->signature_pattern, method_sig))
		{
			return entry;
		}
	}

	return NULL;
}

static inline int
should_process_class(const pattern_filter_t *filter, const char *class_sig)
{
	/* If no filters configured, don't cache anything */
	if (filter->num_entries == 0)
		return 0;

	/* Never process our tracking class */
	// if (strcmp(TRACKER_CLASS, class_sig) == 0)
	// 	return 0;

	/* Check if any filter pattern could match this class */
	for (size_t i = 0; i < filter->num_entries; i++)
	{
		if (config_pattern_match(filter->entries[i].class_pattern, class_sig))
			return 1;
	}

	return 0;
}

static void JNICALL
class_load_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jclass klass)
{
	UNUSED(jni_env);
	UNUSED(thread);

	/* Get class signature for filtering */
	char *class_sig = NULL;
	jvmtiError err =
	    (*jvmti_env)->GetClassSignature(jvmti_env, klass, &class_sig, NULL);
	if (err != JVMTI_ERROR_NONE || class_sig == NULL)
		return;

	/* Class filtered out, skip processing */
	// Lorg/springframework/web/servlet/config/annotation/AsyncSupportConfigurer;
	if (!should_process_class(&global_ctx->unified_filter, class_sig))
		goto cleanup;

	// LOG_INFO("Class load callback, processing %s", class_sig);

	/* Create global reference for the class */
	jclass global_class_ref = (*jni_env)->NewGlobalRef(jni_env, klass);
	if (global_class_ref == NULL)
	{
		LOG_ERROR("Failed to create global reference for class: %s", class_sig);
		goto cleanup;
	}

	/* Class passed filter, enqueue for background processing */
	arena_t *q_entry_arena = global_ctx->arenas[Q_ENTRY_ARENA_ID];
	q_entry_t *entry       = arena_alloc(q_entry_arena, sizeof(q_entry_t));
	class_q_entry_t *class_entry =
	    arena_alloc(q_entry_arena, sizeof(class_q_entry_t));

	if (!entry || !class_entry)
	{
		LOG_ERROR("Unable to allocate room from arena for q entries!");
		goto cleanup;
	}

	class_entry->class_sig = class_sig;
	class_entry->klass     = global_class_ref;

	entry->type = Q_ENTRY_CLASS;
	entry->data = class_entry;

	if (q_enq(global_ctx->class_queue, entry) != 0)
	{
		LOG_ERROR("Failed to enqueue class: %s\n", class_sig);
		/* Clean up the global reference if we couldn't enqueue */
		(*jni_env)->DeleteGlobalRef(jni_env, global_class_ref);
		/* Release entry mem back to arena on enqueue failure */
		arena_free(q_entry_arena, entry);
		arena_free(q_entry_arena, class_entry);
	}

cleanup:
	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)class_sig);
}

static char *
class_name_to_sig(const char *name)
{
	/* Nothing to do if name is NULL*/
	if (!name)
		return NULL;

	/* Use scratch arena */
	arena_t *arena = global_ctx->arenas[SCRATCH_ARENA_ID];
	/* We need "L" + name + ";" + '\0' */
	char *sig = arena_alloc(arena, strlen(name) + 3);
	sprintf(sig, "L%s;", name);
	return sig;
}

static void JNICALL
class_file_load_callback(jvmtiEnv *jvmti_env,
                         JNIEnv *jni_env,
                         jclass class_being_redefined,
                         jobject loader,
                         const char *name,
                         jobject protection_domain,
                         jint class_data_len,
                         const unsigned char *class_data,
                         jint *new_class_data_len,
                         unsigned char **new_class_data)
{

	UNUSED(jni_env);
	UNUSED(class_being_redefined);
	UNUSED(loader);
	UNUSED(protection_domain);
	UNUSED(class_data_len);

	/* Never process our tracking class */
	if (strcmp(TRACKER_CLASS, name) == 0)
		return;

	/* Fast filter check */
	char *sig = class_name_to_sig(name);

	if (!sig)
		return;

	if (!should_process_class(&global_ctx->unified_filter, sig))
		return; /* No modification - use original class */

	LOG_DEBUG("injecting bytecode for %s", name);
	/* Get the temp bytecode arena and rest */
	arena_t *bc_arena = global_ctx->arenas[BYTECODE_ARENA_ID];
	arena_reset(bc_arena);

	/* Parse the class file */
	class_file_t *cf         = NULL;
	bytecode_result_e bc_res = bytecode_parse_class(bc_arena, class_data, &cf);

	if (bc_res != BYTECODE_SUCCESS || !cf)
	{
		LOG_WARN("Failed to parse class %s, using original", name);
		return;
	}

	/* Injection config for native callbacks */
	injection_config_t cfg = {
	    .callback_class = TRACKER_CLASS,
	    .entry_method   = "onMethodEntry",
	    .exit_method    = "onMethodExit",
	    .entry_sig      = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
	    .exit_sig = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"};

	/* Inject */
	bc_res = injection_add_method_tracking(bc_arena, cf, &cfg);

	if (bc_res != BYTECODE_SUCCESS)
	{
		LOG_WARN("Failed to inject tracking into class %s, using original", name);
		return;
	}

	/* Serialize modified class to bytecode */
	u1 *mod_bytecode;
	u4 mod_sz;
	bc_res = bytecode_write_class(bc_arena, cf, &mod_bytecode, &mod_sz);

	if (bc_res != BYTECODE_SUCCESS)
	{
		LOG_WARN("Failed to serialize modified class %s, using original", name);
		return;
	}

	unsigned char *jvmti_buf;
	jvmtiError err = (*jvmti_env)->Allocate(jvmti_env, mod_sz, &jvmti_buf);

	if (err != JVMTI_ERROR_NONE)
	{
		LOG_WARN("JVMTI allocation failed for class %s, using original", name);
		return;
	}

	/* Copy modified bytecode */
	memcpy(jvmti_buf, mod_bytecode, mod_sz);

	/* Return modified class to JVM */
	*new_class_data     = jvmti_buf;
	*new_class_data_len = mod_sz;

	LOG_DEBUG("Successfully injected tracking into class %s (%d -> %d bytes)",
	          name,
	          class_data_len,
	          mod_sz);
}

static uint64_t
get_current_thread_id()
{
	jvmtiEnv *jvmti_env = global_ctx->jvmti_env;
	jvmtiPhase jvm_phase;
	if ((*jvmti_env)->GetPhase(jvmti_env, &jvm_phase) != JVMTI_ERROR_NONE
	    || jvm_phase != JVMTI_PHASE_LIVE)
	{
		LOG_ERROR("Cannot get the thread id as jvm is not in correct phase: %d",
		          jvm_phase);
		return 0;
	}

	jthread current_thread;
	jvmtiError err = (*jvmti_env)->GetCurrentThread(jvmti_env, &current_thread);
	if (err != JVMTI_ERROR_NONE)
	{
		LOG_ERROR("GetCurrentThread failed with error %d", err);
		return 0;
	}

	// TODO finish me

	return 0;
}

/* Record method events via queue system */
void
record_method_event(method_event_type_e event_type,
                    const char *class_name,
                    const char *method_name,
                    const char *method_sig)
{
	/* Reuse your existing queue infrastructure */
	arena_t *q_entry_arena = global_ctx->arenas[Q_ENTRY_ARENA_ID];
	q_entry_t *entry       = arena_alloc(q_entry_arena, sizeof(q_entry_t));
	method_q_entry_t *method_entry =
	    arena_alloc(q_entry_arena, sizeof(method_q_entry_t));

	if (!entry || !method_entry)
	{
		LOG_ERROR("Failed to allocate queue entry for method event");
		return;
	}

	/* Populate method event */
	method_entry->event_type  = event_type;
	method_entry->class_name  = arena_strdup(q_entry_arena, class_name);
	method_entry->method_name = arena_strdup(q_entry_arena, method_name);
	method_entry->method_sig  = arena_strdup(q_entry_arena, method_sig);
	method_entry->timestamp   = get_current_time_ns();
	method_entry->thread_id   = get_current_thread_id();

	if (event_type == METHOD_ENTRY)
		method_entry->cpu = cycles_start();
	else
		method_entry->cpu = cycles_end();

	entry->type = Q_ENTRY_METHOD;
	entry->data = method_entry;

	/* Enqueue for background processing */
	if (q_enq(global_ctx->method_queue, entry) != 0)
	{
		LOG_ERROR("Failed to enqueue method event");
		arena_free(q_entry_arena, entry);
		arena_free(q_entry_arena, method_entry);
	}
}

JNIEXPORT void JNICALL
Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodEntry(JNIEnv *env,
                                                                  jclass clazz,
                                                                  jstring className,
                                                                  jstring methodName,
                                                                  jstring methodSignature)
{
	UNUSED(clazz);

	// LOG_INFO("JNICALL onMethodEntry");

	/* Convert Java strings to C strings */
	const char *class_cstr  = (*env)->GetStringUTFChars(env, className, NULL);
	const char *method_cstr = (*env)->GetStringUTFChars(env, methodName, NULL);
	const char *sig_cstr    = (*env)->GetStringUTFChars(env, methodSignature, NULL);

	/* Record entry event using your existing infrastructure */
	record_method_event(METHOD_ENTRY, class_cstr, method_cstr, sig_cstr);

	/* Release strings */
	(*env)->ReleaseStringUTFChars(env, className, class_cstr);
	(*env)->ReleaseStringUTFChars(env, methodName, method_cstr);
	(*env)->ReleaseStringUTFChars(env, methodSignature, sig_cstr);
}

JNIEXPORT void JNICALL
Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodExit(JNIEnv *env,
                                                                 jclass clazz,
                                                                 jstring className,
                                                                 jstring methodName,
                                                                 jstring methodSignature)
{
	UNUSED(clazz);

	// LOG_INFO("JNICALL onMethodExit");

	const char *class_cstr  = (*env)->GetStringUTFChars(env, className, NULL);
	const char *method_cstr = (*env)->GetStringUTFChars(env, methodName, NULL);
	const char *sig_cstr    = (*env)->GetStringUTFChars(env, methodSignature, NULL);

	record_method_event(METHOD_EXIT, class_cstr, method_cstr, sig_cstr);

	(*env)->ReleaseStringUTFChars(env, className, class_cstr);
	(*env)->ReleaseStringUTFChars(env, methodName, method_cstr);
	(*env)->ReleaseStringUTFChars(env, methodSignature, sig_cstr);
}

jclass
create_tracker_class(JNIEnv *jni_env)
{

	jclass tracker = (*jni_env)->FindClass(jni_env, TRACKER_CLASS);
	if (tracker != NULL)
	{
		LOG_DEBUG("Found existing tracking class");
		return tracker;
	}

	(*jni_env)->ExceptionClear(jni_env);

	tracker = (*jni_env)->DefineClass(jni_env,
	                                  TRACKER_CLASS,
	                                  NULL,
	                                  TRACKER_CLASS_BYTECODE,
	                                  sizeof(TRACKER_CLASS_BYTECODE));

	if (!tracker)
	{
		LOG_ERROR("Failed to create tracking class from bytecode");
		return NULL;
	}

	return tracker;
}

int
register_native_callbacks(JNIEnv *jni_env)
{
	jclass tracker = create_tracker_class(jni_env);
	if (!tracker)
	{
		LOG_ERROR("Failed to create/find tracker class");
		return COOPER_ERR;
	}

	/* Define native method sigs */
	JNINativeMethod methods[] = {
	    {"onMethodEntry",
	     "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
	     (void *)Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodEntry},
	    {"onMethodExit",
	     "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
	     (void *)Java_com_github_foamdino_cooper_agent_NativeTracker_onMethodExit}};

	jint res = (*jni_env)->RegisterNatives(jni_env, tracker, methods, 2);
	if (res != JNI_OK)
	{
		LOG_ERROR("Failed to register native methods: %d", res);
		return COOPER_ERR;
	}

	LOG_INFO("Successfully registered native tracking methods");
	return COOPER_OK;
}

static void JNICALL
thread_end_callback(jvmtiEnv *jvmti, JNIEnv *jni, jthread thread)
{
	UNUSED(jvmti);

	/* Check we can do anything here before looking up thread context */
	if (!thread)
		return;

	if (!global_ctx->getId_method)
		return;

	// thread_context_t *context = pthread_getspecific(context_key);
	thread_context_t *context = get_thread_local_context();
	if (context)
	{
		/* No need to manually free each call since they're arena-allocated */
		context->sample      = NULL;
		context->stack_depth = 0;

		/* Free the context itself */
		free(context);
		pthread_setspecific(context_key, NULL);
	}

	jlong thread_id = (*jni)->CallLongMethod(jni, thread, global_ctx->getId_method);

	/* Remove from our mapping table */
	pthread_mutex_lock(&global_ctx->tm_ctx.samples_lock);
	for (int i = 0; i < MAX_THREAD_MAPPINGS; i++)
	{
		if (global_ctx->thread_mappings[i].java_thread_id == thread_id)
		{
			global_ctx->thread_mappings[i].java_thread_id   = 0;
			global_ctx->thread_mappings[i].native_thread_id = 0;
			break;
		}
	}
	pthread_mutex_unlock(&global_ctx->tm_ctx.samples_lock);
}

/**
 * Add a method to the metrics structure
 */
int
add_method_to_metrics(agent_context_t *ctx,
                      const char *signature,
                      int sample_rate,
                      unsigned int flags)
{

	assert(ctx != NULL);
	assert(ctx->metrics != NULL);

	method_metrics_soa_t *metrics = ctx->metrics;

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
		LOG_ERROR("Method metrics capacity reached (%zu)\n", metrics->capacity);
		return -1;
	}

	/* Add new entry */
	arena_t *arena = ctx->arenas[METRICS_ARENA_ID];
	if (!arena)
	{
		LOG_ERROR("Could not find metrics arena\n");
		return -1;
	}
	index = metrics->count;

	/* As the values are guaranteed to be 0 by the initial allocation, no need to set
	 * every value here */
	metrics->signatures[index]   = arena_strdup(arena, signature);
	metrics->sample_rates[index] = sample_rate;
	metrics->min_time_ns[index]  = UINT64_MAX;
	metrics->metric_flags[index] = flags;
	metrics->count++;

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
int
load_config(agent_context_t *ctx, const char *cf)
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
	ctx->config.rate                = config.default_sample_rate;
	ctx->config.sample_file_path    = config.sample_file_path;
	ctx->config.export_method       = config.export_method;
	ctx->config.export_interval     = config.export_interval;
	ctx->config.mem_sample_interval = config.mem_sample_interval;
	/* Copy unified filter data from parsed config to agent context */
	ctx->unified_filter.num_entries = config.unified_filter.num_entries;
	ctx->unified_filter.capacity    = config.unified_filter.capacity;

	LOG_INFO("Loaded %zu pattern filters", ctx->unified_filter.num_entries);

	/* No filters configured - this is valid but nothing will be cached */
	if (ctx->unified_filter.num_entries == 0)
	{
		LOG_WARN("No pattern filters configured, no methods will be sampled");
		return COOPER_OK;
	}

	/* Allocate filter entries array in context using config arena */
	ctx->unified_filter.entries = arena_alloc(
	    config_arena, ctx->unified_filter.capacity * sizeof(pattern_filter_entry_t));

	if (!ctx->unified_filter.entries)
	{
		LOG_ERROR("Failed to allocate unified filter entries in context\n");
		return COOPER_ERR;
	}

	/* Copy all filter entries - strings are already allocated in config_arena */
	for (size_t i = 0; i < ctx->unified_filter.num_entries; i++)
	{
		pattern_filter_entry_t *src = &config.unified_filter.entries[i];
		pattern_filter_entry_t *dst = &ctx->unified_filter.entries[i];

		/* Copy the pointers - strings already allocated by config parsing */
		dst->class_pattern     = src->class_pattern;
		dst->method_pattern    = src->method_pattern;
		dst->signature_pattern = src->signature_pattern;
		dst->sample_rate       = src->sample_rate;
		dst->metric_flags      = src->metric_flags;

		LOG_DEBUG("Filter %zu: %s:%s:%s (rate=%d, flags=%u)",
		          i,
		          dst->class_pattern,
		          dst->method_pattern,
		          dst->signature_pattern,
		          dst->sample_rate,
		          dst->metric_flags);
	}

	LOG_INFO("Successfully loaded configuration with %zu unified filters",
	         ctx->unified_filter.num_entries);

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
method_metrics_soa_t *
init_method_metrics(arena_t *arena, size_t initial_capacity)
{
	assert(arena != NULL);

	method_metrics_soa_t *metrics =
	    arena_alloc_aligned(arena, sizeof(method_metrics_soa_t), CACHE_LINE_SZ);
	if (!metrics)
		return NULL;

	metrics->capacity = initial_capacity;

	/* arena_alloc zeroes memory — no need for manual memset */
	metrics->signatures =
	    arena_alloc_aligned(arena, initial_capacity * sizeof(char *), CACHE_LINE_SZ);
	metrics->sample_rates =
	    arena_alloc_aligned(arena, initial_capacity * sizeof(int), CACHE_LINE_SZ);
	metrics->call_counts = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	// metrics->sample_counts = arena_alloc_aligned(
	//     arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->total_time_ns = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->min_time_ns = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->max_time_ns = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->alloc_bytes = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->peak_memory = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->cpu_cycles = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->call_sample_counts = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(uint64_t), CACHE_LINE_SZ);
	metrics->metric_flags = arena_alloc_aligned(
	    arena, initial_capacity * sizeof(unsigned int), CACHE_LINE_SZ);

	/* Check if all allocations succeeded */
	if (!metrics->signatures || !metrics->sample_rates
	    || !metrics->call_counts
	    /*|| !metrics->sample_counts*/
	    || !metrics->total_time_ns || !metrics->min_time_ns || !metrics->max_time_ns
	    || !metrics->alloc_bytes || !metrics->peak_memory || !metrics->cpu_cycles
	    || !metrics->call_sample_counts || !metrics->metric_flags)
	{
		return NULL;
	}

	/* Set min_time_ns to maximum value initially */
	for (size_t i = 0; i < initial_capacity; i++)
		metrics->min_time_ns[i] = UINT64_MAX;

	return metrics;
}

static int
precache_loaded_classes(jvmtiEnv *jvmti_env, JNIEnv *jni_env)
{
	int class_count;
	jclass *classes;
	jvmtiError err =
	    (*jvmti_env)->GetLoadedClasses(jvmti_env, &class_count, &classes);

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

		char *class_sig = NULL;
		jvmtiError err =
		    (*jvmti_env)
			->GetClassSignature(jvmti_env, classes[i], &class_sig, NULL);

		/* No class sig, we cannot process this one */
		if (err != JVMTI_ERROR_NONE || class_sig == NULL)
			continue;

		/* Class filtered out, skip processing */
		if (!should_process_class(&global_ctx->unified_filter, class_sig))
			goto deallocate;

		/* Create a global reference for the class */
		jclass global_class_ref = (*jni_env)->NewGlobalRef(jni_env, classes[i]);
		if (global_class_ref == NULL)
		{
			LOG_ERROR("Failed to create global reference for class: %s",
			          class_sig);
			goto deallocate;
		}

		/* Passed filter, enqueue for background processing */
		arena_t *q_entry_arena = global_ctx->arenas[Q_ENTRY_ARENA_ID];
		q_entry_t *entry       = arena_alloc(q_entry_arena, sizeof(q_entry_t));
		class_q_entry_t *class_entry =
		    arena_alloc(q_entry_arena, sizeof(class_q_entry_t));

		if (!entry || !class_entry)
		{
			LOG_ERROR("Unable to allocate room from arena for q entries!");
			goto deallocate;
		}

		class_entry->class_sig = class_sig;
		/* Use the GLOBAL reference, not the local one */
		class_entry->klass = global_class_ref;

		entry->type = Q_ENTRY_CLASS;
		entry->data = class_entry;

		if (q_enq(global_ctx->class_queue, entry) != 0)
		{
			LOG_ERROR("Failed to enqueue class: %s\n", class_sig);
			/* Clean up the global reference if we couldn't enqueue */
			(*jni_env)->DeleteGlobalRef(jni_env, global_class_ref);
			/* Release entry mem back to arena on enqueue failure */
			arena_free(q_entry_arena, entry);
			arena_free(q_entry_arena, class_entry);
		}

	deallocate:
		(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)class_sig);
	}

	(*jvmti_env)->Deallocate(jvmti_env, (unsigned char *)classes);
	LOG_INFO("Completed pre-caching of loaded classes");
	return COOPER_OK;
}

/**
 * Callback to execute any code after the JVM has completed initialisation (after
 * Agent_OnLoad)
 */
static void JNICALL
vm_init_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread)
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
	global_ctx->java_thread_class =
	    (*jni_env)->NewGlobalRef(jni_env, local_thread_class);

	if (global_ctx->java_thread_class == NULL)
	{
		LOG_ERROR("Failed to create global reference for Thread class");
		goto error;
	}

	/* Cache the method ID */
	global_ctx->getId_method = (*jni_env)->GetMethodID(
	    jni_env, global_ctx->java_thread_class, "getId", "()J");

	if (global_ctx->getId_method == NULL)
	{
		LOG_ERROR("Failed to get Thread.getId method ID");
		goto error;
	}

	if (register_native_callbacks(jni_env) != COOPER_OK)
	{
		LOG_ERROR("Failed to register native class");
		goto error;
	}
	LOG_INFO("Native callbacks registered.");

	/* Release local reference */
	(*jni_env)->DeleteLocalRef(jni_env, local_thread_class);
	LOG_INFO("Successfully initialized Thread class and getId method");

	/* Start all background threads */
	if (start_all_threads(global_ctx) != COOPER_OK)
	{
		LOG_ERROR("Failed to start background threads");
		goto error;
	}

	if (precache_loaded_classes(jvmti_env, jni_env) != COOPER_OK)
	{
		LOG_ERROR("Unable to precache loaded classes");
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
	/* In all cases if we reach here we want to exit as the environment is incorrect
	 */
	exit(1);
}

static int
init_jvm_capabilities(agent_context_t *ctx)
{
	assert(ctx != NULL);

	if (!ctx)
		return COOPER_ERR;

	jvmtiCapabilities capabilities;
	jvmtiError err;

	/* Enable capabilities */
	memset(&capabilities, 0, sizeof(capabilities));
	capabilities.can_generate_method_entry_events    = 1;
	capabilities.can_generate_method_exit_events     = 1;
	capabilities.can_generate_exception_events       = 1;
	capabilities.can_access_local_variables          = 1;
	capabilities.can_get_source_file_name            = 1;
	capabilities.can_get_line_numbers                = 1;
	capabilities.can_generate_vm_object_alloc_events = 1;
	capabilities.can_tag_objects                     = 1;
	capabilities.can_generate_all_class_hook_events  = 1;

	err = (*global_ctx->jvmti_env)
	          ->AddCapabilities(global_ctx->jvmti_env, &capabilities);
	if (err != JVMTI_ERROR_NONE)
	{
		LOG_ERROR("AddCapabilities failed with error %d\n", err);
		return COOPER_ERR;
	}

	/* Set event callbacks */
	memset(
	    &ctx->callbacks.event_callbacks, 0, sizeof(ctx->callbacks.event_callbacks));

	// ctx->callbacks.event_callbacks.Exception     = &exception_callback;

	ctx->callbacks.event_callbacks.VMObjectAlloc     = &object_alloc_callback;
	ctx->callbacks.event_callbacks.ThreadEnd         = &thread_end_callback;
	ctx->callbacks.event_callbacks.VMInit            = &vm_init_callback;
	ctx->callbacks.event_callbacks.ClassPrepare      = &class_load_callback;
	ctx->callbacks.event_callbacks.ClassFileLoadHook = &class_file_load_callback;

	err = (*global_ctx->jvmti_env)
	          ->SetEventCallbacks(global_ctx->jvmti_env,
	                              &ctx->callbacks.event_callbacks,
	                              sizeof(ctx->callbacks.event_callbacks));
	if (err != JVMTI_ERROR_NONE)
	{
		LOG_ERROR("SetEventCallbacks failed with error %d\n", err);
		return COOPER_ERR;
	}

	/* The events we want to monitor */
	jvmtiEvent events[] = {JVMTI_EVENT_METHOD_ENTRY,
	                       JVMTI_EVENT_METHOD_EXIT,
	                       JVMTI_EVENT_EXCEPTION,
	                       JVMTI_EVENT_EXCEPTION_CATCH,
	                       JVMTI_EVENT_VM_OBJECT_ALLOC,
	                       JVMTI_EVENT_THREAD_END,
	                       JVMTI_EVENT_VM_INIT,
	                       JVMTI_EVENT_CLASS_LOAD,
	                       JVMTI_EVENT_CLASS_PREPARE,
	                       JVMTI_EVENT_CLASS_FILE_LOAD_HOOK};

	for (size_t i = 0; i < sizeof(events) / sizeof(events[0]); ++i)
	{
		err = (*global_ctx->jvmti_env)
		          ->SetEventNotificationMode(
			      global_ctx->jvmti_env, JVMTI_ENABLE, events[i], NULL);
		if (err != JVMTI_ERROR_NONE)
		{
			LOG_ERROR("SetEventNotificationMode for event %d failed with "
			          "error %d\n",
			          events[i],
			          err);
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
static void
cleanup(agent_context_t *ctx)
{
	/* check if we have work to do */
	if (ctx->config.filters)
	{
		/* Only free the array of pointers, strings are handled by config_arena */
		free(ctx->config.filters);
	}

	/* Reset config values (no need to free arena allocated strings) */
	ctx->config.filters          = NULL;
	ctx->config.num_filters      = 0;
	ctx->config.sample_file_path = NULL;
	ctx->config.export_method    = NULL;
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL
Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
	UNUSED(reserved);

	/* Allocate and initialize the agent context */
	global_ctx = calloc(1, sizeof(agent_context_t));
	if (!global_ctx)
	{
		printf("Failed to allocate agent context\n");
		return JNI_ERR;
	}
	global_ctx->config.rate                = 1;
	global_ctx->config.export_interval     = 60;
	global_ctx->config.mem_sample_interval = 1;
	pthread_mutex_init(&global_ctx->tm_ctx.samples_lock, NULL);
	pthread_mutex_init(&global_ctx->tm_ctx.method_event_lock, NULL);

	/* Redirect output */
	if (options && strncmp(options, "logfile=", 8) == 0)
	{
		global_ctx->log_file = fopen(options + 8, "w");
		if (!global_ctx->log_file)
		{
			printf("Failed to open log file: %s, reverting to stdout\n",
			       options + 8);
			global_ctx->log_file = stdout;
		}
	}

	if (options && strstr(options, "loglevel=debug"))
		current_log_level = LOG_LEVEL_DEBUG;

	q_t *log_queue = calloc(1, sizeof(q_t));

	/*
	  We initialise all the arenas we need in this function and we
	  destroy all the arenas in the corresponding Agent_OnUnload
	*/

	/* Create each arena from the configuration table */
	for (size_t i = 0; i < ARENA_ID__LAST; i++)
	{
		arena_t *arena = arena_init(arena_configs[i].name,
		                            arena_configs[i].size,
		                            arena_configs[i].block_count);

		if (!arena)
		{
			printf("Failed to create %s with id: %ld\n",
			       arena_configs[i].name,
			       arena_configs[i].id);
			return JNI_ERR;
		}

		global_ctx->arenas[arena_configs[i].id] = arena;
	}

	/* make interesting classes available for class file load callback */
	global_ctx->interesting_classes =
	    ht_create(global_ctx->arenas[CLASS_CACHE_ARENA_ID],
	              1000,
	              0.75,
	              hash_string,
	              cmp_string);

	/* cache for jmethodid -> method_info_t */
	global_ctx->interesting_methods =
	    ht_create(global_ctx->arenas[METHOD_CACHE_ARENA_ID],
	              1000,
	              0.75,
	              hash_jmethodid,
	              cmp_jmethodid);

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

	q_t *class_queue = calloc(1, sizeof(q_t));
	if (q_init(class_queue) != COOPER_OK)
	{
		cleanup(global_ctx);
		return JNI_ERR;
	}
	global_ctx->class_queue = class_queue;

	q_t *method_queue = calloc(1, sizeof(q_t));
	if (q_init(method_queue) != COOPER_OK)
	{
		cleanup(global_ctx);
		return JNI_ERR;
	}
	global_ctx->method_queue = method_queue;

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
	size_t initial_capacity = 10000;
	global_ctx->metrics     = init_method_metrics(metrics_arena, initial_capacity);
	if (!global_ctx->metrics)
	{
		LOG_ERROR("Failed to initialize metrics structure\n");
		return JNI_ERR;
	}

	LOG_DEBUG("Metrics arena usage before object init: %zu / %zu bytes\n",
	          metrics_arena->used,
	          metrics_arena->total_sz);

	/* Add object allocation metrics initialization */
	global_ctx->object_metrics =
	    init_object_allocation_metrics(metrics_arena, MAX_OBJECT_TYPES);
	if (!global_ctx->object_metrics)
	{
		LOG_ERROR("Failed to initialize object allocation metrics structure\n");
		return JNI_ERR;
	}

	LOG_DEBUG("Metrics arena usage after object init: %zu / %zu bytes\n",
	          metrics_arena->used,
	          metrics_arena->total_sz);

	global_ctx->app_memory_metrics =
	    arena_alloc(metrics_arena, sizeof(app_memory_metrics_t));
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

	/* Initialize ring channel */
	if (ring_channel_init(&global_ctx->call_stack_channel,
	                      CALL_STACK_CHANNEL_CAPACITY,
	                      sizeof(call_stack_sample_t))
	    != COOPER_OK)
	{
		LOG_ERROR("Failed to init call_stack_channel");
		return JNI_ERR;
	}

	/* Grab a copy of the JVM pointer */
	global_ctx->jvm = vm;

	/* Get JVMTI environment */
	jint result =
	    (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
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
	         global_ctx->config.rate,
	         global_ctx->config.export_method,
	         global_ctx->config.sample_file_path);

	if (strcmp(global_ctx->config.export_method, "file") != 0)
	{
		LOG_ERROR("Unknown export method: [%s]",
		          global_ctx->config.export_method);
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
JNIEXPORT void JNICALL
Agent_OnUnload(JavaVM *vm)
{
	if (global_ctx)
	{
		/* Stop all threads */
		stop_all_threads(global_ctx);

		/* Only if we have a valid JNI environment */
		JNIEnv *jni_env = NULL;
		if ((*vm)->GetEnv(vm, (void **)&jni_env, JNI_VERSION_1_6) == JNI_OK
		    && jni_env != NULL)
		{
			/* Release global reference to Thread class if it exists */
			if (global_ctx->java_thread_class != NULL)
			{
				(*jni_env)->DeleteGlobalRef(
				    jni_env, global_ctx->java_thread_class);
				global_ctx->java_thread_class = NULL;
			}
			/* No need to explicitly free method IDs as they're invalidated
			 * when the class is unloaded */
		}

		cleanup(global_ctx);

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

		/* Note: Any other thread that was using TLS will have its destructor
		called when that thread exits. If the JVM creates a lot of threads that
		don't exit, there could still be leaks. This is a limitation of the
		pthreads API. */
		LOG_WARN("Thread-local storage cleanup may be incomplete for threads "
		         "that don't exit\n");

		if (global_ctx->app_memory_metrics)
		{
			pthread_mutex_destroy(&global_ctx->app_memory_metrics->lock);
			global_ctx->app_memory_metrics = NULL;
			/* when the arena is destroyed, this memory will be reclaimed */
		}

		/* Finally shutdown logging */
		cleanup_log_system();

		ring_channel_free(&global_ctx->call_stack_channel);

		/* Cleanup the arenas - this will free all cache managers and cache data
		 */
		destroy_all_arenas(global_ctx->arenas, ARENA_ID__LAST);
		/* Null out metrics */
		global_ctx->metrics        = NULL;
		global_ctx->object_metrics = NULL;

		/* Destroy mutex */
		pthread_mutex_destroy(&global_ctx->tm_ctx.samples_lock);
		pthread_mutex_destroy(&global_ctx->tm_ctx.method_event_lock);

		free(global_ctx);
		global_ctx = NULL;
	}
	printf("JVMTI Agent Unloaded.\n");
}
