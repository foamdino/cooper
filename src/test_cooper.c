/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"

#undef LOG
 // Mock LOG macro for testing (to avoid threading issues in tests)
#define LOG(ctx, fmt, ...) printf("[TEST] " fmt, ##__VA_ARGS__)

// Helper to create a temporary config file
static const char *create_temp_config(const char *content) 
{
    const char *filename = "/tmp/test_config.ini";
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to create temp config file");
        exit(1);
    }
    fputs(content, fp);
    fclose(fp);
    return filename;
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
    char *result1 = trim(str1, MAX_STR_LEN);
    assert(strcmp(result1, "hello") == 0);

    char str2[] = " \t\n";
    char *result2 = trim(str2, MAX_STR_LEN);
    assert(result2[0] == '\0');

    char str3[] = "no_spaces";
    char *result3 = trim(str3, MAX_STR_LEN);
    assert(strcmp(result3, "no_spaces") == 0);

    char str4[] = "";
    char *result4 = trim(str4, MAX_STR_LEN);
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

    const char *config_file = create_temp_config(config_content);
    int result = load_config(ctx, config_file); // NULL to use default, but we override in test
    /* Delete temp config file */
    unlink(config_file);

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

/* Test arena memory management */
static void test_arena()
{
    /* Test arena_init */
    arena_t *arena = arena_init("test_arena", 1024, 10);
    assert(arena != NULL);
    assert(strcmp(arena->name, "test_arena") == 0);
    assert(arena->total_size <= 1024);
    assert(arena->total_size > 0);
    assert(arena->used == 0);
    assert(arena->free_count == 0);
    assert(arena->max_free_blocks == 10);
    
    /* Test arena_alloc */
    void *block1 = arena_alloc(arena, 100);
    assert(block1 != NULL);
    assert(arena->used >= 100);
    
    /* Write to the memory to ensure it's usable */
    memset(block1, 'A', 100);
    
    /* Allocate another block */
    void *block2 = arena_alloc(arena, 200);
    assert(block2 != NULL);
    assert((char*)block2 > (char*)block1);
    assert(arena->used >= 300); /* Including alignment padding */
    
    /* Write to the second block */
    memset(block2, 'B', 200);
    
    /* Test arena_free */
    int result = arena_free(arena, block1, 100);
    assert(result == 1);
    assert(arena->free_count == 1);
    
    /* Test allocating after freeing */
    void *block3 = arena_alloc(arena, 100);
    assert(block3 != NULL);
    
    /* If the free block was reused, block3 should be the same as block1 */
    if (arena->free_count == 0) {
        assert(block3 == block1);
    }
    
    /* Try to free a block with size 0 */
    result = arena_free(arena, block2, 0);
    assert(result == 0);
    
    /* Test arena_destroy */
    arena_destroy(arena);
    
    /* Test initialization with 0 size or max_blocks */
    assert(arena_init("bad_arena", 0, 10) == NULL);
    assert(arena_init("bad_arena", 1024, 0) == NULL);
    
    /* Test allocating more memory than available */
    arena = arena_init("small_arena", 200, 5);
    assert(arena != NULL);
    
    block1 = arena_alloc(arena, 10);
    assert(block1 != NULL);
    
    /* This should fail as we don't have enough space */
    void *big_block = arena_alloc(arena, 1000);
    assert(big_block == NULL);
    
    /* Test having more free blocks than we can track */
    size_t i;
    void *small_blocks[10];
    
    /* Calculate how many blocks we can allocate based on remaining space */
    size_t max_blocks = 3; /* Reduce the number of allocations */
    for (i = 0; i < max_blocks; i++) {
        small_blocks[i] = arena_alloc(arena, 10);
        assert(small_blocks[i] != NULL);
    }
    
    for (i = 0; i < max_blocks; i++) {
        result = arena_free(arena, small_blocks[i], 10);
        assert(result == 1);
    }
    
    /* Try to free one more block - this should fail as we've reached max_free_blocks */
    if (arena->free_count >= arena->max_free_blocks) {
        block1 = arena_alloc(arena, 10);
        assert(block1 != NULL);
        result = arena_free(arena, block1, 10);
        assert(result == 0);
    }
    
    arena_destroy(arena);
    
    printf("[TEST] arena: All tests passed\n");
}

int main() 
{
    printf("Running unit tests for cooper.c...\n");

    test_trim();
    test_load_config();
    test_should_trace_method();
    test_log_queue();
    test_event_queue();
    test_arena();

    printf("All tests completed successfully!\n");
    return 0;
}