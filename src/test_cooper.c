/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"

#undef LOG
 // Mock LOG macro for testing (to avoid threading issues in tests)
#define LOG(ctx, fmt, ...) printf("[TEST] " fmt, ##__VA_ARGS__)

// Helper to create a temporary config file
static FILE *create_temp_config(const char *content, char *filename) 
{
    FILE *fp = tmpfile();
    if (!fp) {
        perror("Failed to create temp file");
        exit(1);
    }
    fputs(content, fp);
    rewind(fp);

    if (fp == NULL)
        return NULL;

    int fd = fileno(fp);
    if (fd == -1)
        return NULL;

    char buf[256];

    // Construct the path to the temporary file in /proc/self/fd
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

    // Read the actual file path
    ssize_t len = readlink(proc_path, buf, sizeof(buf) - 1);
    if (len == -1)
        return NULL;

    // Null-terminate the filename
    buf[len] = '\0';
    filename = strdup(buf);

    return fp;
}

// Helper to free agent_context_t config fields
static void free_config(agent_context_t *ctx) 
{
    cleanup(ctx); // Reuse your cleanup function
    pthread_mutex_destroy(&ctx->samples_lock);
    free(ctx);
}

// Test trim function
static void test_trim() 
{
    char str1[] = "  hello  \n";
    char *result1 = trim(str1);
    assert(strcmp(result1, "hello") == 0);

    char str2[] = " \t\n";
    char *result2 = trim(str2);
    assert(result2[0] == '\0');

    char str3[] = "no_spaces";
    char *result3 = trim(str3);
    assert(strcmp(result3, "no_spaces") == 0);

    char str4[] = "";
    char *result4 = trim(str4);
    assert(result4[0] == '\0');

    printf("[TEST] trim: All tests passed\n");
}

// Test load_config with a simple config
static void test_load_config() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    pthread_mutex_init(&ctx->samples_lock, NULL);

    const char *config_content =
        "[sample_rate]\n"
        "rate = 5\n"
        "[method_signatures]\n"
        "filters = [\n"
        "\"LTest;\"\n"
        "]\n"
        "[sample_file_location]\n"
        "path = /tmp/test.txt\n"
        "[export]\n"
        "method = file\n"
        "interval = 30\n";

    char filename[256];
    FILE *fp = create_temp_config(config_content, filename);
    assert(fp != NULL);
    int result = load_config(ctx, filename); // NULL to use default, but we override in test
    fclose(fp);

    assert(result == 0);
    assert(ctx->config.rate == 5);
    assert(ctx->config.num_filters == 1);
    assert(strcmp(ctx->config.filters[0], "\"LTest;\"") == 0);
    assert(strcmp(ctx->config.sample_file_path, "/tmp/test.txt") == 0);
    assert(strcmp(ctx->config.export_method, "file") == 0);
    assert(ctx->config.export_interval == 30);

    free_config(ctx);
    printf("[TEST] load_config: All tests passed\n");
}

// Test should_trace_method
static void test_should_trace_method() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    pthread_mutex_init(&ctx->samples_lock, NULL);

    ctx->num_filters = 2;
    ctx->method_filters = malloc(2 * sizeof(char *));
    ctx->method_filters[0] = strdup("\"LTest;\"");
    ctx->method_filters[1] = strdup("\"LFoo;\"");

    assert(should_trace_method(ctx, "LTest;", "method", "()V") == 1);
    assert(should_trace_method(ctx, "LBar;", "method", "()V") == 0);
    assert(should_trace_method(ctx, "LFoo;", "other", "()V") == 1);

    free(ctx->method_filters[0]);
    free(ctx->method_filters[1]);
    free(ctx->method_filters);
    free_config(ctx);
    printf("[TEST] should_trace_method: All tests passed\n");
}

// Test log_enq and log_deq
static void test_log_queue() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    assert(init_log_q(ctx) == 0);

    log_enq(ctx, "Test message 1\n");
    log_enq(ctx, "Test message 2\n");

    char *msg1 = log_deq(ctx);
    assert(msg1 != NULL);
    assert(strcmp(msg1, "Test message 1\n") == 0);
    free(msg1);

    char *msg2 = log_deq(ctx);
    assert(msg2 != NULL);
    assert(strcmp(msg2, "Test message 2\n") == 0);
    free(msg2);

    char *msg3 = log_deq(ctx);
    assert(msg3 == NULL);

    cleanup_log_system(ctx);
    free_config(ctx);
    printf("[TEST] log_queue: All tests passed\n");
}

// Test event_enq and event_deq
static void test_event_queue() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    assert(init_event_q(ctx) == 0);

    event_enq(ctx, "LTest;", "method", "()V", 1);

    trace_event_t e;
    assert(event_deq(ctx, &e) == 1);
    assert(strcmp(e.class_sig, "LTest;") == 0);
    assert(strcmp(e.method_name, "method") == 0);
    assert(strcmp(e.method_sig, "()V") == 0);
    assert(e.is_entry == 1);

    free(e.class_sig);
    free(e.method_name);
    free(e.method_sig);

    assert(event_deq(ctx, &e) == 0);

    cleanup_event_system(ctx);
    free_config(ctx);
    printf("[TEST] event_queue: All tests passed\n");
}

int main() 
{
    printf("Running unit tests for cooper.c...\n");

    test_trim();
    test_load_config();
    test_should_trace_method();
    test_log_queue();
    test_event_queue();

    printf("All tests completed successfully!\n");
    return 0;
}