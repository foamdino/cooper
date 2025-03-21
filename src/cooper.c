#include <jvmti.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define config_file "trace.ini"
#define MAX_SIG_SZ 1024 /**< The max size of a class/method sig we are willing to tolerate */

static jvmtiEnv *jvmti_env = NULL;
static char **method_filters = NULL;
static int num_filters = 0;

void JNICALL method_entry_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method);
void JNICALL method_exit_callback(jvmtiEnv *jvmti, JNIEnv* jni, jthread thread, jmethodID method, jboolean was_popped_by_exception, jvalue return_value);
int should_trace_method(const char *class_signature, const char *method_name, const char *method_signature);
int load_config(const char *cf);
void cleanup_filters(int nf);

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
        printf("ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &declaring_class);
    if (err != JVMTI_ERROR_NONE) {
        printf("ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    err = (*jvmti_env)->GetClassSignature(jvmti_env, declaring_class, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        printf("ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[ENTRY] Method from class %s: %s invoked\n", class_signature, method_name);
    // }

    // TODO need to also count the calls - need a histogram style datastructure - or maxheap (bounded mem)
    if (should_trace_method(class_signature, method_name, method_signature)) 
        printf("[ENTRY] Method from class (%s): %s invoked\n", class_signature, method_name);

    // printf("[ENTRY] %s%s in class %s\n", methodName, methodSignature, classSignature);

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
        printf("ERROR: GetMethodName failed with error %d\n", err);
        goto deallocate;
    }

    // Get declaring class
    err = (*jvmti_env)->GetMethodDeclaringClass(jvmti_env, method, &declaringClass);
    if (err != JVMTI_ERROR_NONE) {
        printf("ERROR: GetMethodDeclaringClass failed with error %d\n", err);
        goto deallocate;
    }

    // Get class signature
    err = (*jvmti_env)->GetClassSignature(jvmti_env, declaringClass, &class_signature, NULL);
    if (err != JVMTI_ERROR_NONE) {
        printf("ERROR: GetClassSignature failed with error %d\n", err);
        goto deallocate;
    }

    // if (strcmp(class_signature, "Lcom/github/foamdino/Test;") == 0 &&
    //     strcmp(method_name, "a") == 0) {
    //     printf("[EXIT] Method from class%s: %s\n", class_signature, method_name);
    // }
    
    // TODO count exits from method - same as entry traces
    if (should_trace_method(class_signature, method_name, method_signature))
        printf("[EXIT] Method from class (%s): %s\n", class_signature, method_name);

    // printf("[EXIT]  %s%s in class %s\n", methodName, methodSignature, classSignature);

deallocate:
    // Deallocate memory allocated by JVMTI
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_name);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)method_signature);
    (*jvmti_env)->Deallocate(jvmti_env, (unsigned char*)class_signature);
}

int load_config(const char *cf)
{
    printf("INFO: loading config from: %s, config_file: %s\n", cf, config_file);
    if (!cf) 
        cf = config_file;

    
    FILE *fp = fopen(cf, "r");
    if (!fp) 
    {
        printf("ERROR: Could not open config file: %s\n", config_file);
        return 1;
    }

    char line[256];
    num_filters = 0;

    // Count lines first
    while (fgets(line, sizeof(line), fp)) {
        num_filters++;
    }
    rewind(fp);

    // Allocate memory for filters
    method_filters = (char **)malloc(num_filters * sizeof(char *));
    if (method_filters == NULL)
    {
        printf("ERROR: Failed to allocate memory for filters\n");
        fclose(fp);
        return 1;
    }
    int i = 0;

    // Read filters
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0; // Remove newline
        method_filters[i] = strdup(line);
        if (method_filters[i] == NULL)
        {
            printf("ERROR: Failed to duplicate string %s for filter %d\n", line, i);
            cleanup_filters(i);
            fclose(fp);
            return 1;
        }
        i++;
    }

    fclose(fp);

    return 0;
}

/**
 * Check if a method matches the filter
 */
int should_trace_method(const char *class_signature, const char *method_name, const char *method_signature) {
    /* Need to size this including spaces and null terminator */
    size_t buf_sz = strlen(class_signature) + strlen(method_name) + strlen(method_signature) + 3;

    char full_signature[MAX_SIG_SZ];
    int written = snprintf(full_signature, sizeof(full_signature), "%s %s %s", class_signature, method_name, method_signature);

    // printf("filter: %s signature: %s, class_sig: %s, method_name: %s, method_sig: %s\n", method_filters[0], full_signature, class_signature, method_name, method_signature);

    if (written < 0 || written >= MAX_SIG_SZ)
    {
        /* snprintf has truncated this method name so we cannot trust this value */
        printf("WARN: Method signature too long for buffer (%d chars)\n", written);
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

    // load config
    if (load_config("./trace.ini") != 0)
    {
        printf("ERROR: Unable to load config_file!\n");
        return JNI_ERR;
    }

    /* Get JVMTI environment */
    jint result = (*vm)->GetEnv(vm, (void **)&jvmti_env, JVMTI_VERSION_1_2);
    if (result != JNI_OK || jvmti_env == NULL) 
    {
        printf("ERROR: Unable to access JVMTI!\n");
        return JNI_ERR;
    }

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

    printf("JVMTI Agent Loaded.\n");
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
    
    for (int i = 0; i < nf; i++) {
        if (method_filters[i] != NULL)
            free(method_filters[i]);
    }
    free(method_filters);

    /* reset state */
    method_filters = NULL;
    num_filters = 0;
}

/**
 * JVMTI Agent Unload Function
 */
JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cleanup_filters(num_filters);
    printf("JVMTI Agent Unloaded.\n");
}