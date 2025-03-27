/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"

static int sample_rate = 1; /**< Default: every event */
static int event_counter = 0; /**< Global counter for nth samples */

static method_stats_t full_samples[FULL_SAMPLE_SZ];
static int full_hd = 0;
static int full_count = 0;

static method_stats_t nth_samples[NTH_SAMPLE_SZ];
static int nth_hd = 0;
static int nth_count = 0;

static jvmtiEnv *jvmti_env = NULL;
static char **method_filters = NULL;
static int num_filters = 0;

/* Logging support */
static log_q_t lq = {0};
static FILE *log_file = NULL;
static pthread_t log_thread;

/* Trace support */
static event_q_t eq = {0};
static pthread_t event_thread;

/* Export samples support */
static pthread_t export_thread;
static pthread_mutex_t samples_lock = PTHREAD_MUTEX_INITIALIZER;

/* Config */
static config_t cfg = {1, NULL, 0, NULL, NULL, 60};

void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value);
int should_trace_method(const char *class_signature, const char *method_name, const char *method_signature);
int load_config(const char *cf);
void cleanup(int nf);

static int start_thread(pthread_t *thread, thread_fn *tf, char *name);


static int init_log_q()
{
    lq.hd = 0;
    lq.tl = 0;
    lq.count = 0;
    lq.running = 1;

    int err;

    err = pthread_mutex_init(&lq.lock, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&lq.cond, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init log q condition: %d\n", err);
        return 1;
    }

    /* TODO: This is hardcoded to STDOUT for now*/
    log_file = stdout;
    return 0;
}

/**
 * Enqueue a msg to the log q 
 * 
 * @param msg Pointer to msg to add
 * 
 * */
static void log_enq(const char *msg)
{
    /* Obtain lock to q */
    pthread_mutex_lock(&lq.lock);

    if (lq.count < LOG_Q_SZ)
    {
        lq.messages[lq.hd] = strdup(msg);
        if (lq.messages[lq.hd])
        {
            lq.hd = (lq.hd + 1) % LOG_Q_SZ;
            lq.count++;
            pthread_cond_signal(&lq.cond);
        }
    }
    else /* Drop messages when q is full */
        fprintf(stderr, "WARNING: logging q full, dropping: %s\n", msg);

    pthread_mutex_unlock(&lq.lock);
}

/**
 * Deuque a message from the log q
 * 
 * @retval Pointer to a char message
 */
static char *log_deq()
{
    char *msg = NULL;
    pthread_mutex_lock(&lq.lock);

    if (lq.count > 0)
    {
        msg = lq.messages[lq.tl];
        lq.messages[lq.tl] = NULL;
        lq.tl = (lq.tl + 1) % LOG_Q_SZ;
        lq.count--;
    }

    pthread_mutex_unlock(&lq.lock);
    return msg;
}

static void *log_thread_func(void *arg)
{
    while (1)
    {
        pthread_mutex_lock(&lq.lock);

        /* Should we exit? */
        if (!lq.running && lq.count == 0)
        {
            pthread_mutex_unlock(&lq.lock);
            break;
        }

        /* Wait for messages when q is empty */
        while (lq.running && lq.count == 0)
            pthread_cond_wait(&lq.cond, &lq.lock);

        if (lq.count > 0)
        {
            char *msg = lq.messages[lq.tl];
            lq.messages[lq.tl] = NULL;
            lq.tl = (lq.tl + 1) % LOG_Q_SZ;
            lq.count--;
            pthread_mutex_unlock(&lq.lock);

            /* We assume that messages have a trailing new line here - we could check and add if missing */
            fprintf(log_file, "%s", msg);
            fflush(log_file);
            free(msg);
        }
        else /* Nothing to do so release lock */
            pthread_mutex_unlock(&lq.lock);    
    }

    return NULL;
}

static int start_thread(pthread_t *thread, thread_fn *fun, char *name)
{
    int err = 0;
    err = pthread_create(thread, NULL, fun, NULL);
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

static void cleanup_log_system()
{
    pthread_mutex_lock(&lq.lock);
    lq.running = 0;
    pthread_cond_broadcast(&lq.cond);
    pthread_mutex_unlock(&lq.lock);

    /* Purge remaining messages */
    char *msg;
    while ((msg = log_deq()) != NULL)
    {
        fprintf(log_file, "%s\n", msg);
        free(msg);
    }

    if (log_file != stdout && log_file != stderr)
        fclose(log_file);

    pthread_cond_destroy(&lq.cond);
    pthread_mutex_destroy(&lq.lock);
}

static void init_samples()
{
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        full_samples[i].signature = NULL;
        full_samples[i].entry_count = 0;
        full_samples[i].exit_count = 0;
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        nth_samples[i].signature = NULL;
        nth_samples[i].entry_count = 0;
        nth_samples[i].exit_count = 0;
    }
}

static void cleanup_samples()
{
    for (int i = 0; i < FULL_SAMPLE_SZ; i++)
    {
        if (full_samples[i].signature)
        {
            free(full_samples[i].signature);
            full_samples[i].signature = NULL;
        }
    }
    for (int i = 0; i < NTH_SAMPLE_SZ; i++)
    {
        if (nth_samples[i].signature)
        {
            free(nth_samples[i].signature);
            nth_samples[i].signature = NULL;
        }
    }
    full_hd = full_count = nth_hd = nth_count = 0;
}

static int init_event_q()
{
    eq.hd = 0;
    eq.tl = 0;
    eq.count = 0;
    eq.running = 1;
    int err = 0;

    err = pthread_mutex_init(&eq.lock, NULL);
    if (err != 0)
    {
        LOG("ERROR: Failed to init event q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&eq.cond, NULL);
    if (err != 0)
    {
        LOG("ERROR: Failed to init event q condition: %d\n", err);
        return 1;
    }

    return 0;
}

static void event_enq(const char *class_sig, const char *method_name, const char *method_sig, int is_entry)
{
    pthread_mutex_lock(&eq.lock);
    if (eq.count < EVENT_Q_SZ)
    {
        trace_event_t *e = &eq.events[eq.hd];
        e->class_sig = strdup(class_sig);
        e->method_name = strdup(method_name);
        e->method_sig = strdup(method_sig);
        e->is_entry = is_entry;

        if (!e->class_sig || !e->method_name || !e->method_sig) 
        {
            LOG("ERROR: Failed to strdup event strings");
            free(e->class_sig);    // Cleanup on failure
            free(e->method_name);
            free(e->method_sig);
            e->class_sig = e->method_name = e->method_sig = NULL;
        } 
        else 
        {
            eq.hd = (eq.hd + 1) % EVENT_Q_SZ;
            eq.count++;
            pthread_cond_signal(&eq.cond);
        }
    }
    else
        LOG("WARNING: Event queue full, dropping event for %s %s %s", class_sig, method_name, method_sig);

    pthread_mutex_unlock(&eq.lock);
}

static int event_deq(trace_event_t *e)
{
    pthread_mutex_lock(&eq.lock);

    if (eq.count > 0)
    {
        *e = eq.events[eq.tl];
        eq.tl = (eq.tl + 1) % EVENT_Q_SZ;
        eq.count--;
        pthread_mutex_unlock(&eq.lock);
        return 1;
    }

    pthread_mutex_unlock(&eq.lock);
    return 0;
}

static void *event_thread_func(void *arg)
{
    trace_event_t e;
    while (1)
    {
        pthread_mutex_lock(&eq.lock);

        if (!eq.running && eq.count == 0)
        {
            pthread_mutex_unlock(&eq.lock);
            break;
        }

        while (eq.running && eq.count == 0)
            pthread_cond_wait(&eq.cond, &eq.lock);

        if (eq.count > 0)
        {
            e = eq.events[eq.tl];
            // TODO check this logic should we increment when taking from the tail?
            eq.tl = (eq.tl + 1) % EVENT_Q_SZ;
            eq.count--;
            pthread_mutex_unlock(&eq.lock);

            /* Now we copy the sig/method strings */
            char full_sig[MAX_SIG_SZ];
            int written = snprintf(full_sig, sizeof(full_sig), "%s %s %s", e.class_sig, e.method_name, e.method_sig);
            if (written < 0 || written >= MAX_SIG_SZ) {
                LOG("WARNING: Full signature truncated: %s %s %s", e.class_sig, e.method_name, e.method_sig);
            }
            for (int i=0; i < full_count; i++)
            {
                int idx = (full_hd + i) % FULL_SAMPLE_SZ;
                if (full_samples[idx].signature && strcmp(full_samples[idx].signature, full_sig) == 0)
                {
                    e.is_entry ? full_samples[idx].entry_count++ : full_samples[idx].exit_count++;
                    goto nth_sampling;
                }
            }
            if (full_count < FULL_SAMPLE_SZ)
            {
                full_samples[full_count].signature = strdup(full_sig);
                full_samples[full_count].entry_count = e.is_entry ? 1 : 0;
                full_samples[full_count].exit_count = e.is_entry ? 0 : 1;
                full_count++;
            }
            else
            {
                int idx = full_hd;
                if (full_samples[idx].signature)
                    free(full_samples[idx].signature);

                full_samples[idx].signature = strdup(full_sig);
                full_samples[idx].entry_count = e.is_entry ? 1 : 0;
                full_samples[idx].exit_count = e.is_entry ? 0 : 1;
                full_hd = (full_hd + 1) % FULL_SAMPLE_SZ;
            }

nth_sampling:
            event_counter++;
            if (event_counter % sample_rate == 0)
            {
                for (int i = 0; i < nth_count; i++)
                {
                    int idx = (nth_hd + i) % NTH_SAMPLE_SZ;
                    if (nth_samples[idx].signature && strcmp(nth_samples[idx].signature, full_sig) == 0)
                    {
                        e.is_entry ? nth_samples[idx].entry_count++ : nth_samples[idx].exit_count++;
                        goto cleanup;
                    }
                }
                if (nth_count < NTH_SAMPLE_SZ)
                {
                    nth_samples[nth_count].signature = strdup(full_sig);
                    nth_samples[nth_count].entry_count = e.is_entry ? 1 : 0;
                    nth_samples[nth_count].exit_count = e.is_entry ? 0 : 1;
                    nth_count++;
                }
                else
                {
                    int idx = nth_hd;
                    if (nth_samples[idx].signature)
                        free(nth_samples[idx].signature);

                    nth_samples[idx].signature = strdup(full_sig);
                    nth_samples[idx].entry_count = e.is_entry ? 1 : 0;
                    nth_samples[idx].exit_count = e.is_entry ? 0 : 1;
                    nth_hd = (nth_hd + 1) % NTH_SAMPLE_SZ;
                }
            }
cleanup:
            free(e.class_sig);
            free(e.method_name);
            free(e.method_sig);
            continue;
        }        
        pthread_mutex_unlock(&eq.lock);
    }
    return NULL;
}

static void cleanup_event_system()
{
    pthread_mutex_lock(&eq.lock);
    eq.running = 0;
    pthread_cond_broadcast(&eq.cond);
    pthread_mutex_unlock(&eq.lock);

    /* TODO Purge remaining events
    Not sure this is required
    while (dequeue_event(&event))

    */
   cleanup_samples();
   pthread_cond_destroy(&eq.cond);
   pthread_mutex_destroy(&eq.lock);
}

static void export_to_file()
{
    FILE *fp = fopen(cfg.sample_file_path, "w");
    if (!fp) 
    {
        LOG("ERROR: Failed to open sample file: %s", cfg.sample_file_path);
        return;
    }

    pthread_mutex_lock(&samples_lock);
    fprintf(fp, "# Full Samples (every event)\n");
    LOG("Exporting full samples to file: %d", full_count);
    for (int i = 0; i < full_count; i++) {
        int idx = (full_hd + i) % FULL_SAMPLE_SZ;
        LOG("%d full sample for sig %s", idx, full_samples[idx].signature);
        if (full_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    full_samples[idx].signature, 
                    full_samples[idx].entry_count, 
                    full_samples[idx].exit_count);
        }
    }
    fprintf(fp, "# Nth Samples (every %d events)\n", sample_rate);
    for (int i = 0; i < nth_count; i++) {
        int idx = (nth_hd + i) % NTH_SAMPLE_SZ;
        LOG("%d nth sample for sig %s", idx, nth_samples[idx].signature);
        if (nth_samples[idx].signature) {
            fprintf(fp, "%s entries=%d exits=%d\n", 
                    nth_samples[idx].signature, 
                    nth_samples[idx].entry_count, 
                    nth_samples[idx].exit_count);
        }
    }
    pthread_mutex_unlock(&samples_lock);

    fclose(fp);
}

static void *export_thread_func(void *arg) 
{
    /* Reuse event_queue.running as a global stop flag */
    while (eq.running) { 
        export_to_file();
        sleep(cfg.export_interval);
    }

    /* Final write on shutdown */
    export_to_file(); 
    return NULL;
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

    err = (*jvmti_env)->GetMethodName(jvmti_env, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti_env)->GetClassSignature(jvmti_env, declaring_class, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[ENTRY] Method from class %s: %s invoked\n", class_signature, method_name);
    // }

    // TODO need to also count the calls - need a histogram style datastructure - or maxheap (bounded mem)
    if (should_trace_method(class_signature, method_name, method_signature))
    {
        event_enq(class_signature, method_name, method_signature, 1);
        LOG("[ENTRY] Method from class (%s): %s invoked\n", class_signature, method_name);
    } 
        


deallocate:
    // Deallocate memory allocated by JVMTI
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_signature);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_signature);
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

    // Get method name
    err = (*jvmti_env)->GetMethodName(jvmti_env, method, &method_name, &method_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    // Get declaring class
    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &declaringClass);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    // Get class signature
    err = (*jvmti_env)->GetClassSignature(jvmti_env, declaringClass, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        LOG("ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[EXIT] Method from class%s: %s\n", class_signature, method_name);
    // }
    
    // TODO count exits from method - same as entry traces
    if (should_trace_method(class_signature, method_name, method_signature))
    {
        event_enq(class_signature, method_name, method_signature, 0);
        LOG("[EXIT] Method from class (%s): %s\n", class_signature, method_name);
    }

deallocate:
    // Deallocate memory allocated by JVMTI
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_signature);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_signature);
}

int load_config(const char *cf)
{
    LOG("INFO: loading config from: %s, config_file: %s\n", cf, config_file);
    if (!cf) 
        cf = config_file;

    
    FILE *fp = fopen(cf, "r");
    if (!fp) 
    {
        LOG("ERROR: Could not open config file: %s\n", config_file);
        return 1;
    }

    char line[256];
    char *section = NULL;
    int in_filters;

    while (fgets(line, sizeof(line), fp))
    {
        char *trimmed = trim(line);
        strip_comment(trimmed);

        /* skip empty lines or comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#') 
            continue;

        /* Start of a section */
        if (trimmed[0] == '[')
        {
            if (section) 
                free(section); // Free previous section before reassigning
            
            section = strdup(trimmed);
            if (!section) 
            {
                LOG("ERROR: Failed to allocate memory for section");
                fclose(fp);
                return 1;
            }
            in_filters = (strcmp(section, "[method_signatures]") == 0);
            continue;
        }

        if (section)
        {
            if (strcmp(section, "[sample_rate]") == 0)
            {
                char *value = extract_and_trim_value(trimmed);
                if (value) 
                {
                    int rate;
                    if (sscanf(value, "%d", &rate) == 1) 
                    {
                        cfg.rate = rate > 0 ? rate : 1;
                        sample_rate = cfg.rate;
                    }
                }
            } 
            else if (strcmp(section, "[method_signatures]") == 0)
            {
                if (strncmp(trimmed, "filters =", 9) == 0)
                {
                    in_filters = 1;
                }
                else if (in_filters && trimmed[0] != ']')
                {
                    cfg.num_filters++;
                    char **tmp = realloc(cfg.filters, cfg.num_filters * sizeof(char *));
                    if (!tmp)
                    {
                        LOG("ERROR: Failed to allocate memory for filters");
                        fclose(fp);
                        return 1;
                    }
                    cfg.filters = tmp;
                    cfg.filters[cfg.num_filters - 1] = strdup(trimmed);
                }
            }
            else if (strcmp(section, "[sample_file_location]") == 0) 
            {
                char *value = extract_and_trim_value(trimmed);
                if (value) {
                    char *new_path = strdup(value);
                    if (!new_path) {
                        LOG("ERROR: Failed to duplicate path: %s", value);
                    } else {
                        if (cfg.sample_file_path) free(cfg.sample_file_path);
                        cfg.sample_file_path = new_path;
                    }
                }
            } 
            else if (strcmp(section, "[export]") == 0) 
            {
                char *value;

                if (strstr(trimmed, "method")) {
                    value = extract_and_trim_value(trimmed);
                    if (value) {
                        char *new_method = strdup(value);
                        if (!new_method) {
                            LOG("ERROR: Failed to duplicate method: %s", value);
                        } else {
                            if (cfg.export_method) free(cfg.export_method);
                            cfg.export_method = new_method;
                        }
                    }
                }

                if (strstr(trimmed, "interval")) {
                    value = extract_and_trim_value(trimmed);
                    if (value) {
                        if (sscanf(value, "%d", &cfg.export_interval) != 1) {
                            LOG("WARNING: Invalid interval value: %s", value);
                        }
                    }
                }
            }
        }
    }

    if (section) 
        free(section);

    fclose(fp);
    method_filters = cfg.filters;
    num_filters = cfg.num_filters;

    return 0;
}

/**
 * Check if a method matches the filter
 */
int should_trace_method(const char *class_signature, const char *method_name, const char *method_signature) {

    /* This is a fixed size as we cannot afford mallocs in this hot code path */
    char full_signature[MAX_SIG_SZ];
    int written = snprintf(full_signature, sizeof(full_signature), "%s %s %s", class_signature, method_name, method_signature);

    // printf("filter: %s signature: %s, class_sig: %s, method_name: %s, method_sig: %s\n", method_filters[0], full_signature, class_signature, method_name, method_signature);

    if (written < 0 || written >= MAX_SIG_SZ)
    {
        /* snprintf has truncated this method name so we cannot trust this value */
        LOG("WARN: Method signature too long for buffer (%d chars)\n", written);
        return 0;
    }
    
    for (int i = 0; i < num_filters; i++) {
        //printf("filter: %s signature: %s", method_filters[i], full_signature);
        // if (strcmp(method_filters[i], full_signature) == 0) {
        //     return 1; // Match found
        // }
        if (strstr(method_filters[i], class_signature))
            return 1;
    }
    return 0; // No match
}

/*
 * Entry point
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    jvmtiCapabilities capabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError err;

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || jvmti_env == NULL) 
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return JNI_ERR;
    }

    /* Init logging */
    if (init_log_q() != 0)
    {
        cleanup(num_filters);
        return JNI_ERR;
    }
    if (start_thread(&log_thread, &log_thread_func, "log") != 0)
    {
        cleanup(num_filters);
        cleanup_log_system();
        return JNI_ERR;
    }

    /* Redirect output */
    if (options && strncmp(options, "logfile=", 8) == 0)
    {
        log_file = fopen(options + 8, "w");
        if (!log_file)
        {
            printf("ERROR: Failed to open log file: %s, reverting to stdout\n", options + 8);
            log_file = stdout;
        }
    }

    /* Now we have logging configured, load config */
    if (load_config("./trace.ini") != 0)
    {
        LOG("ERROR: Unable to load config_file!\n");
        return JNI_ERR;
    }

    LOG("Config: rate=%d, method='%s', path='%s'",
        cfg.rate, cfg.export_method, cfg.sample_file_path);

    if (strcmp(cfg.export_method, "file") != 0)
    {
        LOG("ERROR: Unknown export method: [%s]", cfg.export_method);
        return JNI_ERR;
    }

    /* Init the event/sample handling */
    if (init_event_q() != 0 || 
        start_thread(&event_thread, &event_thread_func, "event") != 0 || 
        start_thread(&export_thread, &export_thread_func, "export-samples") != 0)
    {
        cleanup(num_filters);
        cleanup_log_system();
        cleanup_event_system();
        return JNI_ERR;
    }

    init_samples();

    /* Enable capabilities */
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.can_generate_method_entry_events = 1;
    capabilities.can_generate_method_exit_events = 1;
    err = (*jvmti_env)->AddCapabilities(jvmti_env, &capabilities);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG("ERROR: AddCapabilities failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;

    err = (*jvmti_env)->SetEventCallbacks(jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG("ERROR: SetEventCallbacks failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Enable event notifications */
    err = (*jvmti_env)->SetEventNotificationMode(jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        LOG("ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*jvmti_env)->SetEventNotificationMode(jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        LOG("ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return JNI_ERR;
    }

    LOG("JVMTI Agent Loaded.\n");
    return JNI_OK;
}

/**
 * Cleanup state
 * 
 * @param nf num filters to clear
 */
void cleanup(int nf)
{
    /* check if we have work to do */
    if (cfg.filters) {
        for (int i = 0; i < nf; i++) {
            if (cfg.filters[i]) 
                free(cfg.filters[i]);
        }
        free(cfg.filters);
    }

    if (cfg.sample_file_path) 
        free(cfg.sample_file_path);

    if (cfg.export_method) 
        free(cfg.export_method);

    cfg.filters = NULL;
    cfg.num_filters = 0;
    cfg.sample_file_path = NULL;
    cfg.export_method = NULL;
    method_filters = NULL;
    num_filters = 0;
}

/**
 * JVMTI Agent Unload Function
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cleanup(num_filters);
    cleanup_samples();
    cleanup_log_system();
    printf("JVMTI Agent Unloaded.\n");
}