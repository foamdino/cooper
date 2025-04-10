/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "arena.h"

static agent_context_t *global_ctx = NULL; /* Single global context */

int init_log_q(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    ctx->log_queue.hd = 0;
    ctx->log_queue.tl = 0;
    ctx->log_queue.count = 0;
    ctx->log_queue.running = 1;

    int err;

    err = pthread_mutex_init(&ctx->log_queue.lock, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&ctx->log_queue.cond, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q condition: %d\n", err);
        return 1;
    }

    /* TODO: This is hardcoded to STDOUT for now*/
    ctx->log_file = stdout;
    return 0;
}

/**
 * Enqueue a msg to the log q 
 * 
 * @param msg Pointer to msg to add
 * 
 * */
void log_enq(agent_context_t *ctx, const char *msg)
{
    assert(ctx != NULL);
    assert(msg != NULL);
    
    /* Obtain lock to q */
    pthread_mutex_lock(&ctx->log_queue.lock);

    if (ctx->log_queue.count < LOG_Q_SZ)
    {
        ctx->log_queue.messages[ctx->log_queue.hd] = strdup(msg);
        if (ctx->log_queue.messages[ctx->log_queue.hd])
        {
            ctx->log_queue.hd = (ctx->log_queue.hd + 1) % LOG_Q_SZ;
            ctx->log_queue.count++;
            pthread_cond_signal(&ctx->log_queue.cond);
        }
    }
    else /* Drop messages when q is full */
        fprintf(stderr, "WARNING: logging q full, dropping: %s\n", msg);

    pthread_mutex_unlock(&ctx->log_queue.lock);
}

/**
 * Deuque a message from the log q
 * 
 * @retval Pointer to a char message
 */
char *log_deq(agent_context_t *ctx)
{
    assert(ctx != NULL);

    char *msg = NULL;
    pthread_mutex_lock(&ctx->log_queue.lock);

    if (ctx->log_queue.count > 0)
    {
        msg = ctx->log_queue.messages[ctx->log_queue.tl];
        ctx->log_queue.messages[ctx->log_queue.tl] = NULL;
        ctx->log_queue.tl = (ctx->log_queue.tl + 1) % LOG_Q_SZ;
        ctx->log_queue.count--;
    }

    pthread_mutex_unlock(&ctx->log_queue.lock);
    return msg;
}

void *log_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;

    while (1)
    {
        pthread_mutex_lock(&ctx->log_queue.lock);

        /* Should we exit? */
        if (!ctx->log_queue.running && ctx->log_queue.count == 0)
        {
            pthread_mutex_unlock(&ctx->log_queue.lock);
            break;
        }

        /* Wait for messages when q is empty */
        while (ctx->log_queue.running && ctx->log_queue.count == 0)
            pthread_cond_wait(&ctx->log_queue.cond, &ctx->log_queue.lock);

        if (ctx->log_queue.count > 0)
        {
            char *msg = ctx->log_queue.messages[ctx->log_queue.tl];
            ctx->log_queue.messages[ctx->log_queue.tl] = NULL;
            ctx->log_queue.tl = (ctx->log_queue.tl + 1) % LOG_Q_SZ;
            ctx->log_queue.count--;
            pthread_mutex_unlock(&ctx->log_queue.lock);

            /* We assume that messages have a trailing new line here - we could check and add if missing */
            fprintf(ctx->log_file, "%s", msg);
            fflush(ctx->log_file);
            free(msg);
        }
        else /* Nothing to do so release lock */
            pthread_mutex_unlock(&ctx->log_queue.lock);    
    }

    return NULL;
}

int start_thread(pthread_t *thread, thread_fn *fun, char *name, agent_context_t *ctx)
{
    int err = 0;
    err = pthread_create(thread, NULL, fun, ctx);
    if (err != 0)
    {
        printf("ERROR: Failed to start %s thread: %d\n", name, err);
        return 1;
    }

    err = pthread_detach(*thread);
    if (err != 0)
    {
        printf("ERROR: Failed to detach %s thread: %d\n", name, err);
        return 1;
    }
    return 0;
}

void cleanup_log_system(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->log_queue.lock);
    ctx->log_queue.running = 0;
    pthread_cond_broadcast(&ctx->log_queue.cond);
    pthread_mutex_unlock(&ctx->log_queue.lock);

    /* Purge remaining messages */
    char *msg;
    while ((msg = log_deq(ctx)) != NULL)
    {
        fprintf(ctx->log_file, "%s\n", msg);
        free(msg);
    }

    if (ctx->log_file != stdout && ctx->log_file != stderr)
        fclose(ctx->log_file);

    pthread_cond_destroy(&ctx->log_queue.cond);
    pthread_mutex_destroy(&ctx->log_queue.lock);
}

void init_samples(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        ctx->full_samples[i].signature = NULL;
        ctx->full_samples[i].entry_count = 0;
        ctx->full_samples[i].exit_count = 0;
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        ctx->nth_samples[i].signature = NULL;
        ctx->nth_samples[i].entry_count = 0;
        ctx->nth_samples[i].exit_count = 0;
    }
}

void cleanup_samples(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        if (ctx->full_samples[i].signature)
        {
            free(ctx->full_samples[i].signature);
            ctx->full_samples[i].signature = NULL;
        }
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        if (ctx->nth_samples[i].signature)
        {
            free(ctx->nth_samples[i].signature);
            ctx->nth_samples[i].signature = NULL;
        }
    }
    ctx->full_hd = ctx->full_count = ctx->nth_hd = ctx->nth_count = 0;
}

int init_event_q(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    ctx->event_queue.hd = 0;
    ctx->event_queue.tl = 0;
    ctx->event_queue.count = 0;
    ctx->event_queue.running = 1;
    int err = 0;

    err = pthread_mutex_init(&ctx->event_queue.lock, NULL);
    if (err != 0)
    {
        LOG(ctx, "ERROR: Failed to init event q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&ctx->event_queue.cond, NULL);
    if (err != 0)
    {
        LOG(ctx, "ERROR: Failed to init event q condition: %d\n", err);
        return 1;
    }

    return 0;
}

void event_enq(agent_context_t *ctx, const char *class_sig, const char *method_name, const char *method_sig, int is_entry)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->event_queue.lock);
    if (ctx->event_queue.count < EVENT_Q_SZ)
    {
        trace_event_t *e = &ctx->event_queue.events[ctx->event_queue.hd];
        e->class_sig = strdup(class_sig);
        e->method_name = strdup(method_name);
        e->method_sig = strdup(method_sig);
        e->is_entry = is_entry;

        if (!e->class_sig || !e->method_name || !e->method_sig) 
        {
            LOG(ctx, "ERROR: Failed to strdup event strings");
            free(e->class_sig);    /* Cleanup on failure */
            free(e->method_name);
            free(e->method_sig);
            e->class_sig = e->method_name = e->method_sig = NULL;
        } 
        else 
        {
            ctx->event_queue.hd = (ctx->event_queue.hd + 1) % EVENT_Q_SZ;
            ctx->event_queue.count++;
            pthread_cond_signal(&ctx->event_queue.cond);
        }
    }
    else
        LOG(ctx, "WARNING: Event queue full, dropping event for %s %s %s", class_sig, method_name, method_sig);

    pthread_mutex_unlock(&ctx->event_queue.lock);
}

int event_deq(agent_context_t *ctx, trace_event_t *e)
{
    assert(ctx != NULL);
    
    pthread_mutex_lock(&ctx->event_queue.lock);

    if (ctx->event_queue.count > 0)
    {
        *e = ctx->event_queue.events[ctx->event_queue.tl];
        ctx->event_queue.tl = (ctx->event_queue.tl + 1) % EVENT_Q_SZ;
        ctx->event_queue.count--;
        pthread_mutex_unlock(&ctx->event_queue.lock);
        return 1;
    }

    pthread_mutex_unlock(&ctx->event_queue.lock);
    return 0;
}

void *event_thread_func(void *arg)
{
    assert(arg != NULL);

    trace_event_t e;
    agent_context_t *ctx = (agent_context_t *)arg;
    
    while (1)
    {
        pthread_mutex_lock(&ctx->event_queue.lock);

        if (!ctx->event_queue.running && ctx->event_queue.count == 0)
        {
            pthread_mutex_unlock(&ctx->event_queue.lock);
            break;
        }

        while (ctx->event_queue.running && ctx->event_queue.count == 0)
            pthread_cond_wait(&ctx->event_queue.cond, &ctx->event_queue.lock);

        if (ctx->event_queue.count > 0)
        {
            e = ctx->event_queue.events[ctx->event_queue.tl];
            /* TODO check this logic should we increment when taking from the tail? */
            ctx->event_queue.tl = (ctx->event_queue.tl + 1) % EVENT_Q_SZ;
            ctx->event_queue.count--;
            pthread_mutex_unlock(&ctx->event_queue.lock);

            /* Now we copy the sig/method strings */
            char full_sig[MAX_SIG_SZ];
            
            int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", e.class_sig, e.method_name, e.method_sig);
            if (written < 0 || written >= MAX_SIG_SZ)
                LOG(ctx, "WARNING: Full signature truncated: %s %s %s", e.class_sig, e.method_name, e.method_sig);
            
            for (int i=0; i < ctx->full_count; i++)
            {
                int idx = (ctx->full_hd + i) % FULL_SAMPLE_SZ;
                if (ctx->full_samples[idx].signature && strcmp(ctx->full_samples[idx].signature, full_sig) == 0)
                {
                    e.is_entry ? ctx->full_samples[idx].entry_count++ : ctx->full_samples[idx].exit_count++;
                    goto nth_sampling;
                }
            }
            if (ctx->full_count < FULL_SAMPLE_SZ)
            {
                /* Copy the full_sig value to the samples signature as full_sig is a stack allocated buffer */
                ctx->full_samples[ctx->full_count].signature = strdup(full_sig);
                /* Set correct info for exit/entry */
                ctx->full_samples[ctx->full_count].entry_count = e.is_entry ? 1 : 0;
                ctx->full_samples[ctx->full_count].exit_count = e.is_entry ? 0 : 1;
                ctx->full_count++;
            }
            else /* We have FULL_SAMPLE_SZ number of samples already */
            {
                /* Set our index to the current hd */
                int idx = ctx->full_hd;
                /* Remove any signature at this location */
                if (ctx->full_samples[idx].signature)
                    free(ctx->full_samples[idx].signature);

                /* Set the signature to the new value */
                ctx->full_samples[idx].signature = strdup(full_sig);
                /* Set correct info for exit/entry */
                ctx->full_samples[idx].entry_count = e.is_entry ? 1 : 0;
                ctx->full_samples[idx].exit_count = e.is_entry ? 0 : 1;
                /* Reset the full_hd position */
                ctx->full_hd = (ctx->full_hd + 1) % FULL_SAMPLE_SZ;
            }

nth_sampling:
            ctx->event_counter++;
            if (ctx->event_counter % ctx->config.rate == 0)
            {
                for (int i = 0; i < ctx->nth_count; i++)
                {
                    int idx = (ctx->nth_hd + i) % NTH_SAMPLE_SZ;
                    if (ctx->nth_samples[idx].signature && strcmp(ctx->nth_samples[idx].signature, full_sig) == 0)
                    {
                        e.is_entry ? ctx->nth_samples[idx].entry_count++ : ctx->nth_samples[idx].exit_count++;
                        goto cleanup;
                    }
                }
                if (ctx->nth_count < NTH_SAMPLE_SZ)
                {
                    ctx->nth_samples[ctx->nth_count].signature = strdup(full_sig);
                    ctx->nth_samples[ctx->nth_count].entry_count = e.is_entry ? 1 : 0;
                    ctx->nth_samples[ctx->nth_count].exit_count = e.is_entry ? 0 : 1;
                    ctx->nth_count++;
                }
                else
                {
                    int idx = ctx->nth_hd;
                    if (ctx->nth_samples[idx].signature)
                        free(ctx->nth_samples[idx].signature);

                    ctx->nth_samples[idx].signature = strdup(full_sig);
                    ctx->nth_samples[idx].entry_count = e.is_entry ? 1 : 0;
                    ctx->nth_samples[idx].exit_count = e.is_entry ? 0 : 1;
                    ctx->nth_hd = (ctx->nth_hd + 1) % NTH_SAMPLE_SZ;
                }
            }
cleanup:
            free(e.class_sig);
            free(e.method_name);
            free(e.method_sig);
            continue;
        }        
        pthread_mutex_unlock(&ctx->event_queue.lock);
    }
    return NULL;
}

void cleanup_event_system(agent_context_t *ctx)
{
    assert(ctx != NULL);

    pthread_mutex_lock(&ctx->event_queue.lock);
    ctx->event_queue.running = 0;
    pthread_cond_broadcast(&ctx->event_queue.cond);
    pthread_mutex_unlock(&ctx->event_queue.lock);

    /* TODO Purge remaining events
    Not sure this is required
    while (dequeue_event(&event))

    */
   cleanup_samples(ctx);
   pthread_cond_destroy(&ctx->event_queue.cond);
   pthread_mutex_destroy(&ctx->event_queue.lock);
}

void export_to_file(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    FILE *fp = fopen(ctx->config.sample_file_path, "w");
    if (!fp) 
    {
        LOG(ctx, "ERROR: Failed to open sample file: %s\n", ctx->config.sample_file_path);
        return;
    }

    pthread_mutex_lock(&ctx->samples_lock);
    fprintf(fp, "# Full Samples (every event)\n");
    for (int i = 0; i < ctx->full_count; i++) {
        int idx = (ctx->full_hd + i) % FULL_SAMPLE_SZ;
        LOG(ctx, "%d full sample for sig %s\n", idx, ctx->full_samples[idx].signature);
        if (ctx->full_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    ctx->full_samples[idx].signature, 
                    ctx->full_samples[idx].entry_count, 
                    ctx->full_samples[idx].exit_count);
        }
    }
    fprintf(fp, "# Nth Samples (every %d events)\n", ctx->config.rate);
    for (int i = 0; i < ctx->nth_count; i++) {
        int idx = (ctx->nth_hd + i) % NTH_SAMPLE_SZ;
        LOG(ctx, "%d nth sample for sig %s\n", idx, ctx->nth_samples[idx].signature);
        if (ctx->nth_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    ctx->nth_samples[idx].signature, 
                    ctx->nth_samples[idx].entry_count, 
                    ctx->nth_samples[idx].exit_count);
        }
    }
    pthread_mutex_unlock(&ctx->samples_lock);

    fclose(fp);
}

void *export_thread_func(void *arg)
{
    assert(arg != NULL);

    agent_context_t *ctx = (agent_context_t *)arg;
    
    /* Reuse event_queue.running as a global stop flag */
    while (ctx->event_queue.running) 
    { 
        export_to_file(ctx);
        sleep(ctx->config.export_interval);
    }

    /* Final write on shutdown */
    export_to_file(ctx); 
    return NULL;
}
/**
 * get a param value for a method
 * 
 * TODO think about how malloc/free works here - cannot have this dynamic memory, need an arena or something
 */
static char *get_parameter_value(jvmtiEnv *jvmti, JNIEnv *jni_env, 
    jthread thread, jmethodID method, jint param_index, jint param_slot, char param_type)
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
                result = arena_alloc(global_ctx->exception_arena, 12);
                if (result)
                    sprintf(result, "%d", value.i);
            }
            break;

        /* long */
        case 'J':
            err = (*jvmti)->GetLocalLong(jvmti, thread, 0, param_slot, &value.j);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(global_ctx->exception_arena, 21);
                if (result)
                    sprintf(result, "%lld", (long long)value.j);
            }
            break;

        /* float */
        case 'F':
            err = (*jvmti)->GetLocalFloat(jvmti, thread, 0, param_slot, &value.f);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(global_ctx->exception_arena, 32);
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
                result = arena_alloc(global_ctx->exception_arena, 32);
                if (result)
                    sprintf(result, "%f", value.d);
            }
            break;

        /* boolean */
        case 'Z':
            err = (*jvmti)->GetLocalInt(jvmti, thread, 0, param_slot, &value.i);
            if (err == JVMTI_ERROR_NONE)
            {
                result = arena_alloc(global_ctx->exception_arena, 6);
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
                result = arena_alloc(global_ctx->exception_arena, 12);
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
                            result = arena_alloc(global_ctx->exception_arena, strlen(str_value) + 3); /* includes quotes and null */
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
                                result = arena_alloc(global_ctx->exception_arena, strlen(str_value) + 1);
                                if (result)
                                    strcpy(result, str_value);

                                (*jni_env)->ReleaseStringUTFChars(jni_env, str, str_value);
                            }
                        }
                        else
                        {
                            result = arena_alloc(global_ctx->exception_arena, 5);
                            if (result)
                                strcpy(result, "null");
                        }
                    }
                }
                else
                {
                    result = arena_alloc(global_ctx->exception_arena, 5);
                    if (result)
                        strcpy(result, "null");
                }
            }
            break;
        
        default:
            result = arena_alloc(global_ctx->exception_arena, 16);
            if (result)
                sprintf(result, "<unknown type>");

            break;
    }

    if (!result)
    {
        result = arena_alloc(global_ctx->exception_arena, 10);
        if (result)
            sprintf(result, "<error>");
    }

    return result;
}

/*
 * Method entry callback
 */
void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method)
{
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaring_class;
    jvmtiError err;

    if (jvmti != global_ctx->jvmti_env)
        LOG(global_ctx, "WARNING: jvmti (%p) differs from global_ctx->jvmti_env (%p)\n", jvmti, global_ctx->jvmti_env);

    err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti)->GetClassSignature(jvmti, declaring_class, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[ENTRY] Method from class %s: %s invoked\n", class_signature, method_name);
    // }

    /* TODO need to also count the calls - need a histogram style datastructure - or maxheap (bounded mem) */
    if (should_trace_method(global_ctx, class_signature, method_name, method_signature))
    {
        event_enq(global_ctx, class_signature, method_name, method_signature, 1);
        LOG(global_ctx, "[ENTRY] Method from class (%s): %s invoked\n", class_signature, method_name);
    } 

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
    char *method_name = NULL;
    char *method_signature = NULL;
    char *class_signature = NULL;
    jclass declaringClass;
    jvmtiError err;

    if (jvmti != global_ctx->jvmti_env)
        LOG(global_ctx, "WARNING: jvmti (%p) differs from global_ctx->jvmti_env (%p)\n", jvmti, global_ctx->jvmti_env);

    /* Get method name */
    err = (*jvmti)->GetMethodName(jvmti, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    /* Get declaring class */
    err = (*jvmti)->GetMethodDeclaringClass(jvmti, method, &declaringClass);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    /* Get class signature */
    err = (*jvmti)->GetClassSignature(jvmti, declaringClass, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[EXIT] Method from class%s: %s\n", class_signature, method_name);
    // }
    
    /* TODO count exits from method - same as entry traces */
    if (should_trace_method(global_ctx, class_signature, method_name, method_signature))
    {
        event_enq(global_ctx, class_signature, method_name, method_signature, 0);
        LOG(global_ctx, "[EXIT] Method from class (%s): %s\n", class_signature, method_name);
    }

deallocate:
    /* Deallocate memory allocated by JVMTI */
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_name);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)method_signature);
    (*jvmti)->Deallocate(jvmti, (unsigned char*)class_signature);
}

/**
 * Exception callback
 */
void JNICALL exception_callback(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread, jmethodID method, jlocation location, jobject exception, jmethodID catch_method, jlocation catch_location)
{
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
        LOG(global_ctx, "ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    jclass method_class;
    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &method_class);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }
    
    /* Get class name */
    err = (*jvmti_env)->GetClassSignature(jvmti_env, method_class, &class_name, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }
        
    /* Convert Java exception to string representation */
    jclass exception_class = (*jni_env)->GetObjectClass(jni_env, exception);
    jmethodID toString_id = (*jni_env)->GetMethodID(jni_env, exception_class, "toString", "()Ljava/lang/String;");
    jstring exception_str = (*jni_env)->CallObjectMethod(jni_env, exception, toString_id);
    if ((*jni_env)->ExceptionCheck(jni_env)) 
    {
        LOG(global_ctx, "ERROR: JNI exception occurred while getting exception string\n");
        (*jni_env)->ExceptionClear(jni_env);
        goto deallocate;
    }
    
    /* Convert to standard C string */
    const char *exception_cstr = exception_str ? (*jni_env)->GetStringUTFChars(jni_env, exception_str, NULL) : "Unknown exception";
    
    LOG(global_ctx, "Exception in %s.%s%s at location %ld\n", class_name, method_name, method_signature, (long)location);
    LOG(global_ctx, "Exception details: %s\n", exception_cstr);
    
    /* Get the local variable table for this method */
    jint entry_count = 0;
    err = (*jvmti_env)->GetLocalVariableTable(jvmti_env, method, &entry_count, &table);

    /* all other errors just bail */
    if (err != JVMTI_ERROR_NONE && err != JVMTI_ERROR_ABSENT_INFORMATION)
    {
        LOG(global_ctx, "ERROR: Could not get local variable table %d\n", err);
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

        LOG(global_ctx, "Method params: \n");

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
            char *param_val = get_parameter_value(jvmti_env, jni_env, thread, method, param_idx, slot, param_type);

            LOG(global_ctx, "\tParam %d (%s): %s (sz: %d)\n", 
                param_idx, 
                param_name ? param_name : "<unknown>",
                param_val ? param_val : "<error>",
                sizeof(param_val));

            if (param_val)
            {
                arena_free(global_ctx->exception_arena, param_val, sizeof(param_val));
            }
                
            
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
            LOG(global_ctx, "ERROR: GetMethodName for catch_method failed with error %d\n", err);
            goto deallocate;
        }
        
        LOG(global_ctx, "Caught in method: %s%s at location %ld\n", catch_method_name, catch_method_signature, (long)catch_location);
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
}

/**
 * Load the config from the config file. Uses free directly rather than arena_alloc/free
 */
int load_config(agent_context_t *ctx, const char *cf)
{
    assert(ctx != NULL);
    
    LOG(ctx, "INFO: loading config from: %s, default config_file: %s\n", cf, DEFAULT_CFG_FILE);
    if (!cf) 
        cf = DEFAULT_CFG_FILE;
    
    FILE *fp = fopen(cf, "r");
    if (!fp) 
    {
        LOG(ctx, "ERROR: Could not open config file: %s\n", cf);
        return 1;
    }

    char line[256];
    char *current_section = NULL;

    while (fgets(line, sizeof(line), fp))
    {
        /* clean input line */
        char *trimmed = trim_safe(line);
        trimmed = strip_comment_safe(trimmed);
        /* skip empty lines */
        if (trimmed[0] == '\0')
            continue;

        /* This is a section header, move to the next line for config data */
        if (trimmed[0] == '[')
        {
            if (current_section) 
                free(current_section);
            
            current_section = strdup(trimmed);
            if (!current_section)
            {
                LOG(ctx, "ERROR: Failed to allocate memory for section\n");
                fclose(fp);
                return 1;
            }
            continue;
        }

        /* Skip any data before the first section */
        if (!current_section)
            continue;

        /* Based on the section we're in we can interpret the value differently */
        if (strcmp(current_section, "[method_signatures]") == 0)
        {
            LOG(ctx, "DEBUG: Processing line in [method_signatures]: '%s'\n", trimmed);
            /* Skip over the filters line, end of filters is a line containing a single ']' */
            if (strncmp(trimmed, "filters =", 9) == 0 || trimmed[0] == ']')
                continue;

            /* Process a filter entry */
            ctx->config.num_filters++;
            LOG(ctx, "DEBUG: Adding filter #%d: '%s'\n", ctx->config.num_filters, trimmed);
            /* Adjust filter storage */
            char **tmp = realloc(ctx->config.filters, ctx->config.num_filters * sizeof(char *));
            if (!tmp)
            {
                LOG(ctx, "ERROR: Failed to allocate memory for filters\n");
                free(current_section);
                fclose(fp);
                return 1;
            }
            ctx->config.filters = tmp;

            /* Copy filter value to ctx filter storage */
            ctx->config.filters[ctx->config.num_filters - 1] = strdup(trimmed);
            /* Check we have the new filter */
            if (!ctx->config.filters[ctx->config.num_filters -1])
                LOG(ctx, "ERROR: Failed to duplicate filter: %s\n", trimmed);
        }
        else
        {
            /* Grab the data value from the trimmed line */
            char *value = extract_and_trim_value_safe(trimmed);
            if (!value)
                continue;

            if (strcmp(current_section, "[sample_rate]") == 0)
            {
                int rate;
                if (sscanf(value, "%d", &rate) == 1)
                    ctx->config.rate = rate > 0 ? rate : 1;
            }
            else if (strcmp(current_section, "[sample_file_location]") == 0)
            {
                if (!set_config_string(&ctx->config.sample_file_path, value))
                    LOG(ctx, "ERROR: Failed to duplicate sample_file_path: %s\n", value);
            }
            else if (strcmp(current_section, "[export]") == 0)
            {
                if (strstr(trimmed, "method"))
                {
                    if (!set_config_string(&ctx->config.export_method, value))
                        LOG(ctx, "ERROR: Failed to duplicate export_method: %s\n", value);
                }
                else if (strstr(trimmed, "interval"))
                {
                    if (sscanf(value, "%d", &ctx->config.export_interval) != 1)
                        LOG(ctx, "WARNING: Invalid interval value: %s\n", value);
                }
            }
        }

        if (trimmed)
            free(trimmed);
    }

    free(current_section);
    fclose(fp);

    /* Set defaults and finalize */
    if (!ctx->config.export_method) 
    {
        ctx->config.export_method = strdup("file");
        if (!ctx->config.export_method)
            LOG(ctx, "ERROR: Failed to set default export_method\n");
    }
    ctx->method_filters = ctx->config.filters;
    ctx->num_filters = ctx->config.num_filters;

    LOG(ctx, "Config loaded: rate=%d, filters=%d, path=%s, method=%s\n",
        ctx->config.rate, ctx->num_filters,
        ctx->config.sample_file_path ? ctx->config.sample_file_path : "NULL",
        ctx->config.export_method ? ctx->config.export_method : "NULL");

    return 0;
}

/**
 * Check if a method matches the filter
 */
int should_trace_method(agent_context_t *ctx, const char *class_signature, const char *method_name, const char *method_signature) 
{

    /* This is a fixed size as we cannot afford mallocs in this hot code path */
    char full_signature[MAX_SIG_SZ];
    int written = snprintf(full_signature, sizeof(full_signature), "%s %s %s", class_signature, method_name, method_signature);

    // printf("filter: %s signature: %s, class_sig: %s, method_name: %s, method_sig: %s\n", method_filters[0], full_signature, class_signature, method_name, method_signature);

    if (written < 0 || written >= MAX_SIG_SZ)
    {
        /* snprintf has truncated this method name so we cannot trust this value */
        LOG(ctx, "WARN: Method signature too long for buffer (%d chars)\n", written);
        return 0;
    }
    
    for (int i = 0; i < ctx->num_filters; i++) {
        //printf("filter: %s signature: %s", method_filters[i], full_signature);
        // if (strcmp(method_filters[i], full_signature) == 0) {
        //     return 1; // Match found
        // }
        if (strstr(ctx->method_filters[i], class_signature))
            return 1;
    }
    return 0; /* No match */
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    jvmtiCapabilities capabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError err;

    /* Allocate and initialize the agent context */
    global_ctx = malloc(sizeof(agent_context_t));
    if (!global_ctx) {
        printf("ERROR: Failed to allocate agent context\n");
        return JNI_ERR;
    }
    memset(global_ctx, 0, sizeof(agent_context_t));
    global_ctx->jvmti_env = NULL;
    global_ctx->method_filters = NULL;
    global_ctx->num_filters = 0;
    global_ctx->log_file = NULL;
    global_ctx->config.rate = 1;
    global_ctx->config.filters = NULL;
    global_ctx->config.num_filters = 0;
    global_ctx->config.sample_file_path = NULL;
    global_ctx->config.export_method = NULL;
    global_ctx->config.export_interval = 60;
    pthread_mutex_init(&global_ctx->samples_lock, NULL);

    /* Initialize exception arena */
    /* TODO these numbers need tweaking / investigation */
    size_t exception_arena_sz = 1024 * 1024;
    global_ctx->exception_arena = arena_init("exception_arena", exception_arena_sz, 1024);
    if (!global_ctx->exception_arena) {
        LOG(global_ctx, "ERROR: Failed to create exception arena\n");
        return JNI_ERR;
    }

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&global_ctx->jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || global_ctx->jvmti_env == NULL) 
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    /* Init logging */
    if (init_log_q(global_ctx) != 0)
    {
        cleanup(global_ctx);
        return JNI_ERR;
    }
    if (start_thread(&global_ctx->log_thread, &log_thread_func, "log", global_ctx) != 0)
    {
        cleanup(global_ctx);
        cleanup_log_system(global_ctx);
        return JNI_ERR;
    }

    /* Redirect output */
    if (options && strncmp(options, "logfile=", 8) == 0)
    {
        global_ctx->log_file = fopen(options + 8, "w");
        if (!global_ctx->log_file)
        {
            printf("ERROR: Failed to open log file: %s, reverting to stdout\n", options + 8);
            global_ctx->log_file = stdout;
        }
    }

    /* Now we have logging configured, load config */
    if (load_config(global_ctx, "./trace.ini") != 0)
    {
        LOG(global_ctx, "ERROR: Unable to load config_file!\n");
        return JNI_ERR;
    }

    LOG(global_ctx, "Config: rate=%d, method='%s', path='%s'\n",
        global_ctx->config.rate, global_ctx->config.export_method, global_ctx->config.sample_file_path);

    if (strcmp(global_ctx->config.export_method, "file") != 0)
    {
        LOG(global_ctx, "ERROR: Unknown export method: [%s]", global_ctx->config.export_method);
        return JNI_ERR;
    }

    /* Init the event/sample handling */
    if (init_event_q(global_ctx) != 0 || 
        start_thread(&global_ctx->event_thread, &event_thread_func, "event", global_ctx) != 0 || 
        start_thread(&global_ctx->export_thread, &export_thread_func, "export-samples", global_ctx) != 0)
    {
        cleanup(global_ctx);
        cleanup_log_system(global_ctx);
        cleanup_event_system(global_ctx);
        return JNI_ERR;
    }

    init_samples(global_ctx);

    /* Enable capabilities */
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_method_entry_events = 1;
    capabilities.can_generate_method_exit_events = 1;
    capabilities.can_generate_exception_events = 1;
    capabilities.can_access_local_variables = 1;
    capabilities.can_get_source_file_name = 1;
    capabilities.can_get_line_numbers = 1;

    err = (*global_ctx->jvmti_env)->AddCapabilities(global_ctx->jvmti_env, &capabilities);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: AddCapabilities failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;
    callbacks.Exception = &exception_callback;

    err = (*global_ctx->jvmti_env)->SetEventCallbacks(global_ctx->jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: SetEventCallbacks failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Enable event notifications */
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*global_ctx->jvmti_env)->SetEventNotificationMode(global_ctx->jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_EXCEPTION_CATCH, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG(global_ctx, "ERROR: SetEventNotificationMode for JVMTI_EVENT_EXCEPTION failed with error %d\n", err);
        return JNI_ERR;
    }

    LOG(global_ctx, "JVMTI Agent Loaded.\n");
    return JNI_OK;
}

/**
 * Cleanup state
 * 
 * @param nf num filters to clear
 */
void cleanup(agent_context_t *ctx)
{
    /* check if we have work to do */
    if (ctx->config.filters) {
        for (int i = 0; i < ctx->num_filters; i++) {
            if (ctx->config.filters[i]) 
                free(ctx->config.filters[i]);
        }
        free(ctx->config.filters);
    }

    if (ctx->config.sample_file_path) 
        free(ctx->config.sample_file_path);

    if (ctx->config.export_method) 
        free(ctx->config.export_method);

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
    if (global_ctx) {
        cleanup(global_ctx);
        /* Since the JVM is terminating, we'll just clean up some resources but avoid
           freeing memory that might be in use by the JVM. The OS will reclaim all
           memory when the process exits. */
        cleanup_samples(global_ctx);
        cleanup_log_system(global_ctx);
        cleanup_event_system(global_ctx);
        
        /* Don't free the context - the JVM still might be using it */
        free(global_ctx);
        global_ctx = NULL;    
    }
    printf("JVMTI Agent Unloaded.\n");
}