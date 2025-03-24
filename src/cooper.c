#include <jvmti.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define config_file "trace.ini"
#define EVENT_Q_SZ 2048 /**< An event q buffer */
#define FULL_SAMPLE_SZ 1024 /**< The max entries for the every sample buffer */
#define NTH_SAMPLE_SZ 256 /**< The max entries for the nth sample buffer */
#define MAX_SIG_SZ 1024 /**< The max size of a class/method sig we are willing to tolerate */
#define MAX_LOG_MSG_SZ 1024 /**< The max size of a trace message we will tolerate */
#define LOG_Q_SZ 1024 /**< Length of log q */
#define LOG(fmt, ...) do { \
    char msg[MAX_LOG_MSG_SZ]; \
    int len = snprintf(msg, sizeof(msg), "[JMVTI] " fmt, ##__VA_ARGS__); \
    if (len >= 0 && len < MAX_LOG_MSG_SZ) { \
        log_enq(msg); \
    } \
} while (0)

typedef struct log_q log_q_t;
typedef struct trace_event trace_event_t;
typedef struct event_q event_q_t;
typedef struct method_stats method_stats_t;
typedef struct config config_t;

struct config
{
    int rate;
    char **filters;
    int num_filters;
    char *sample_file_path;
};

struct log_q
{
    char *messages[LOG_Q_SZ];
    int hd;
    int tl;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
};

struct trace_event
{
    char *class_sig;
    char *method_name;
    char *method_sig;
    int is_entry; /**< 1 for entry, 0 for exit */
};

struct event_q
{
    trace_event_t events[EVENT_Q_SZ];
    int hd;
    int tl;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int running;
};

struct method_stats
{
    char *signature;
    int entry_count;
    int exit_count;
};

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

/* Config */
static config_t cfg = {1, NULL, 0, NULL};

void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value);
int should_trace_method(const char *class_signature, const char *method_name, const char *method_signature);
int load_config(const char *cf);
void cleanup_filters(int nf);

static char *trim(char *str)
{
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str) -1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n'))
        *end-- = '\0';
    
    return str;
}

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

static int start_log_thread()
{
    int err = 0;
    err = pthread_create(&log_thread, NULL, log_thread_func, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to start log thread: %d\n", err);
        return 1;
    }

    err = pthread_detach(log_thread);
    if (err != 0)
    {
        printf("ERROR: Failed to detach log thread: %d\n", err);
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
        printf("ERROR: Failed to init event q mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&eq.cond, NULL);
    if (err != 0)
    {
        printf("ERROR: Failed to init event q condition: %d\n", err);
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
        e->class_sig = (char *)class_sig;
        e->method_name = (char *)method_name;
        e->method_sig = (char *)method_sig;
        e->is_entry = is_entry;
        eq.hd = (eq.hd + 1) % EVENT_Q_SZ;
        eq.count++;
        pthread_cond_signal(&eq.cond);
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
            // TODO perhaps check snprintf return here in case of truncation
            snprintf(full_sig, sizeof(full_sig), "%s %s %s", e.class_sig, e.method_name, e.method_sig);

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
            continue;
        }        
        pthread_mutex_unlock(&eq.lock);
    }
    return NULL;
}

static int start_event_thread()
{
    int err = 0;
    err = pthread_create(&event_thread, NULL, &event_thread_func, NULL);
    if (err != 0)
    {
        LOG("ERROR: Failed to start event thread %d", err);
        return 1;
    }

    err = pthread_detach(event_thread);
    if (err != 0)
    {
        LOG("ERROR: Failed to detach event thread %d", err);
        return 1;
    }
    return 0;
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
        /* skip empty lines or comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#') 
            continue;

        /* Start of a section */
        if (trimmed[0] == '[')
        {
            section = strdup(trimmed);
            in_filters = (strcmp(section, "[method_signatures]") == 0);
            continue;
        }

        if (section)
        {
            if (strcmp(section, "[sample_rate]") == 0)
            {
                /* set sample rate */
                if (sscanf(trimmed, "rate = %d", &cfg.rate) == 1)
                    sample_rate = cfg.rate > 0 ? cfg.rate : 1;
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
                if (strncmp(trimmed, "path =", 6) == 0)
                {
                    cfg.sample_file_path = strdup(trimmed + 6);
                }
            }

        }
    }

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
        cleanup_filters(num_filters);
        return JNI_ERR;
    }
    if (start_log_thread() != 0)
    {
        cleanup_filters(num_filters);
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
        printf("ERROR: Unable to load config_file!\n");
        return JNI_ERR;
    }

    /* Init the event/sample handling */
    if (init_event_q() != 0 || start_event_thread() != 0)
    {
        cleanup_filters(num_filters);
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
        printf("ERROR: AddCapabilities failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Set callbacks */
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.MethodEntry = &method_entry_callback;
    callbacks.MethodExit = &method_exit_callback;

    err = (*jvmti_env)->SetEventCallbacks(jvmti_env, &callbacks, sizeof(callbacks));
    if (err != JVMTI_ERROR_NONE) 
    {
        printf("ERROR: SetEventCallbacks failed with error %d\n", err);
        return JNI_ERR;
    }

    /* Enable event notifications */
    err = (*jvmti_env)->SetEventNotificationMode(jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_ENTRY, NULL);
    if (err != JVMTI_ERROR_NONE) 
    {
        printf("ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_ENTRY failed with error %d\n", err);
        return JNI_ERR;
    }
    err = (*jvmti_env)->SetEventNotificationMode(jvmti_env, JVMTI_ENABLE, JVMTI_EVENT_METHOD_EXIT, NULL);
    if (err != JVMTI_ERROR_NONE)
    {
        printf("ERROR: SetEventNotificationMode for JVMTI_EVENT_METHOD_EXIT failed with error %d\n", err);
        return JNI_ERR;
    }

    LOG("JVMTI Agent Loaded.\n");
    return JNI_OK;
}

/**
 * Cleanup filters
 * 
 * @param nf num filters to clear
 */
void cleanup_filters(int nf)
{
    /* check if we have work to do */
    if (method_filters == NULL) return;
 
    if (cfg.filters)
    {
        for (int i = 0; i < nf; i++) {
            if (cfg.filters[i] != NULL)
                free(cfg.filters[i]);
        }
        free(cfg.filters);
    }

    /* reset state */
    if (cfg.sample_file_path)
        free(cfg.sample_file_path);

    cfg.filters = NULL;
    cfg.num_filters = 0;
    cfg.sample_file_path = NULL;
    method_filters = NULL;
    num_filters = 0;
}

/**
 * JVMTI Agent Unload Function
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cleanup_filters(num_filters);
    cleanup_samples();
    cleanup_log_system();
    printf("JVMTI Agent Unloaded.\n");
}