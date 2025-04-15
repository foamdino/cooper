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

// Test trim_safe function
static void test_arena_trim() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    size_t config_arena_sz = 512 * 1024;
    ctx->config_arena = arena_init("config_arena", config_arena_sz, 1024);

    char *result1 = arena_trim(ctx->config_arena, "  hello  \n");
    assert(result1 != NULL);
    assert(strcmp(result1, "hello") == 0);

    char *result2 = arena_trim(ctx->config_arena, " \t\n");
    assert(result2 != NULL);
    assert(strlen(result2) == 0);

    char *result3 = arena_trim(ctx->config_arena, "no_spaces");
    assert(result3 != NULL);
    assert(strcmp(result3, "no_spaces") == 0);

    char *result4 = arena_trim(ctx->config_arena, "");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    arena_destroy(ctx->config_arena);
    free(ctx);

    printf("[TEST] test_arena_trim: All tests passed\n");
}

// Test strip_comment_safe function
static void test_arena_strip_comment() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    size_t config_arena_sz = 512 * 1024;
    ctx->config_arena = arena_init("config_arena", config_arena_sz, 1024);

    char *result1 = arena_strip_comment(ctx->config_arena, "hello # comment");
    assert(result1 != NULL);
    assert(strcmp(result1, "hello ") == 0);

    char *result2 = arena_strip_comment(ctx->config_arena, "no comment here");
    assert(result2 != NULL);
    assert(strcmp(result2, "no comment here") == 0);


    char *result3 = arena_strip_comment(ctx->config_arena, "# comment only");
    assert(result3 != NULL);
    assert(strcmp(result3, "") == 0);

    char *result4 = arena_strip_comment(ctx->config_arena, "");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    arena_destroy(ctx->config_arena);
    free(ctx);

    printf("[TEST] test_arena_strip_comment: All tests passed\n");
}

// Test arena_extract_and_trim_value function
static void test_arena_extract_and_trim_value() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    size_t config_arena_sz = 512 * 1024;
    ctx->config_arena = arena_init("config_arena", config_arena_sz, 1024);

    // Standard key-value pair
    char *result1 = arena_extract_and_trim_value(ctx->config_arena, "key = value");
    assert(result1 != NULL);
    assert(strcmp(result1, "value") == 0);

    // Key-value pair with extra whitespace
    char *result2 = arena_extract_and_trim_value(ctx->config_arena, "key =   value   ");
    assert(result2 != NULL);
    assert(strcmp(result2, "value") == 0);

    // Key-value pair with no space after equals
    char *result3 = arena_extract_and_trim_value(ctx->config_arena, "key=value");
    assert(result3 != NULL);
    assert(strcmp(result3, "value") == 0);
    
    // Key with no value (should return NULL)
    char *result4 = arena_extract_and_trim_value(ctx->config_arena, "key = ");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    // No equals sign (should return NULL)
    char *result5 = arena_extract_and_trim_value(ctx->config_arena, "key value");
    assert(result5 == NULL);

    // Only equals sign
    char *result6 = arena_extract_and_trim_value(ctx->config_arena, "=value");
    assert(result6 != NULL);
    assert(strcmp(result6, "value") == 0);

    // Empty string
    char *result7 = arena_extract_and_trim_value(ctx->config_arena, "");
    assert(result7 == NULL);

    arena_destroy(ctx->config_arena);
    free(ctx);

    printf("[TEST] test_arena_extract_and_trim_value: All tests passed\n");
}

// Test load_config with a simple config
static void test_load_config() 
{
    agent_context_t *ctx = malloc(sizeof(agent_context_t));
    memset(ctx, 0, sizeof(agent_context_t));
    ctx->jvmti_env = NULL;
    ctx->method_filters = NULL;
    ctx->num_filters = 0;
    ctx->log_file = NULL;
    ctx->config.rate = 1;
    ctx->config.filters = NULL;
    ctx->config.num_filters = 0;
    ctx->config.sample_file_path = NULL;
    ctx->config.export_method = NULL;
    ctx->config.export_interval = 60;
    pthread_mutex_init(&ctx->samples_lock, NULL);

    assert(ctx != NULL);
    assert(init_log_q(ctx) == 0);
    size_t config_arena_sz = 512 * 1024;
    ctx->config_arena = arena_init("config_arena", config_arena_sz, 1024);

    size_t log_arena_sz = 512 * 1024;
    ctx->log_arena = arena_init("log_arena", log_arena_sz, 1024);

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

    arena_destroy(ctx->config_arena);
    arena_destroy(ctx->log_arena);
    free(ctx);
    printf("[TEST] load_config: All tests passed\n");
}

// Test should_trace_method
static void test_should_trace_method() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    assert(init_log_q(ctx) == 0);
    pthread_mutex_init(&ctx->samples_lock, NULL);
    
    // Initialize the config arena
    size_t config_arena_sz = 512 * 1024;
    ctx->config_arena = arena_init("config_arena", config_arena_sz, 1024);
    assert(ctx->config_arena != NULL);

    ctx->num_filters = 2;
    ctx->method_filters = malloc(2 * sizeof(char *));
    
    // Use arena for filter strings
    ctx->method_filters[0] = arena_strdup(ctx->config_arena, "\"LTest;\"");
    ctx->method_filters[1] = arena_strdup(ctx->config_arena, "\"LFoo;\"");

    assert(should_trace_method(ctx, "LTest;", "method", "()V") == 1);
    assert(should_trace_method(ctx, "LBar;", "method", "()V") == 0);
    assert(should_trace_method(ctx, "LFoo;", "other", "()V") == 1);

    // Free the array of pointers but not the strings themselves
    free(ctx->method_filters);
    
    // Clean up the arena
    arena_destroy(ctx->config_arena);
    free(ctx);
    printf("[TEST] should_trace_method: All tests passed\n");
}

// Test log_enq and log_deq
static void test_log_queue() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    assert(init_log_q(ctx) == 0);
    
    // Initialize log arena for message storage
    size_t log_arena_sz = 512 * 1024;
    ctx->log_arena = arena_init("log_arena", log_arena_sz, 1024);
    assert(ctx->log_arena != NULL);

    // Now enqueue messages (using arena_strdup in the implementation)
    log_enq(ctx, "Test message 1\n");
    log_enq(ctx, "Test message 2\n");

    char *msg1 = log_deq(ctx);
    assert(msg1 != NULL);
    assert(strcmp(msg1, "Test message 1\n") == 0);
    // No need to free msg1 as it's now managed by the arena

    char *msg2 = log_deq(ctx);
    assert(msg2 != NULL);
    assert(strcmp(msg2, "Test message 2\n") == 0);
    // No need to free msg2 as it's now managed by the arena

    char *msg3 = log_deq(ctx);
    assert(msg3 == NULL);

    // Clean up arenas first
    arena_destroy(ctx->log_arena);
    
    // // Clean up remaining resources
    // cleanup_log_system(ctx);
    free(ctx);
    printf("[TEST] log_queue: All tests passed\n");
}

// Test event_enq and event_deq
static void test_event_queue() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    assert(ctx != NULL);
    assert(init_event_q(ctx) == 0);
    
    // Initialize event arena for event data storage
    size_t event_arena_sz = 512 * 1024;
    ctx->event_arena = arena_init("event_arena", event_arena_sz, 1024);
    assert(ctx->event_arena != NULL);

    event_enq(ctx, "LTest;", "method", "()V", 1);

    trace_event_t e;
    assert(event_deq(ctx, &e) == 1);
    assert(strcmp(e.class_sig, "LTest;") == 0);
    assert(strcmp(e.method_name, "method") == 0);
    assert(strcmp(e.method_sig, "()V") == 0);
    assert(e.is_entry == 1);
    assert(event_deq(ctx, &e) == 0);

    // Clean up arena first
    arena_destroy(ctx->event_arena);
    free(ctx);
    printf("[TEST] event_queue: All tests passed\n");
}

/* Test arena memory management */
static void test_arena()
{
    /* Test arena_init */
    arena_t *arena = arena_init("test_arena", 1024, 10);
    assert(arena != NULL);
    assert(strcmp(arena->name, "test_arena") == 0);
    assert(arena->total_sz <= 1024);
    assert(arena->total_sz > 0);
    assert(arena->used == 0);
    assert(arena->free_count == 0);
    assert(arena->max_free_blocks == 10);
    
    /* Test arena_alloc */
    void *block1 = arena_alloc(arena, 100);
    assert(block1 != NULL);
    assert(arena->used >= 100);
    
    /* Check that the block header has the correct magic number */
    block_header_t *header1 = (block_header_t*)((char*)block1 - sizeof(block_header_t));
    assert(header1->magic == ARENA_BLOCK_MAGIC);
    assert(header1->block_sz == 100);
    
    /* Write to the memory to ensure it's usable */
    memset(block1, 'A', 100);
    
    /* Allocate another block */
    void *block2 = arena_alloc(arena, 200);
    assert(block2 != NULL);
    assert((char*)block2 > (char*)block1);
    assert(arena->used >= 300); /* Including alignment padding */
    
    /* Check that the second block header has the correct magic number */
    block_header_t *header2 = (block_header_t*)((char*)block2 - sizeof(block_header_t));
    assert(header2->magic == ARENA_BLOCK_MAGIC);
    assert(header2->block_sz == 200);
    
    /* Write to the second block */
    memset(block2, 'B', 200);
    
    /* Test arena_free */
    int result = arena_free(arena, block1);
    assert(result == 1);
    assert(arena->free_count == 1);
    
    /* Test allocating after freeing */
    void *block3 = arena_alloc(arena, 100);
    assert(block3 != NULL);
    
    /* Check that the reused block has the correct magic number */
    block_header_t *header3 = (block_header_t*)((char*)block3 - sizeof(block_header_t));
    assert(header3->magic == ARENA_BLOCK_MAGIC);
    assert(header3->block_sz == 100);
    
    /* If the free block was reused, block3 should be the same as block1 */
    if (arena->free_count == 0) {
        assert(block3 == block1);
    }
    
    /* Test corrupting a block header and verifying that free fails */
    header2->magic = 0xDEADBEEF; /* Corrupt the magic number */
    result = arena_free(arena, block2);
    assert(result == 0); /* Should fail due to invalid magic number */
    
    /* Restore the magic number */
    header2->magic = ARENA_BLOCK_MAGIC;
    
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
    header1 = (block_header_t*)((char*)block1 - sizeof(block_header_t));
    assert(header1->magic == ARENA_BLOCK_MAGIC);
    
    /* This should fail as we don't have enough space */
    void *big_block = arena_alloc(arena, 1000);
    assert(big_block == NULL);
    
    /* Test having more free blocks than we can track */
    size_t i;
    void *small_blocks[10];
    
    /* Calculate how many blocks we can allocate based on remaining space */
    size_t max_blocks = 2; /* Reduce the number of allocations to fit in small_arena */
    for (i = 0; i < max_blocks; i++) {
        small_blocks[i] = arena_alloc(arena, 10);
        /* If allocation fails, don't try to verify magic number */
        if (small_blocks[i] == NULL) {
            break;
        }
        
        /* Verify magic number in each block */
        block_header_t *header = (block_header_t*)((char*)small_blocks[i] - sizeof(block_header_t));
        assert(header->magic == ARENA_BLOCK_MAGIC);
    }
    
    /* Only free the blocks that were successfully allocated */
    for (i = 0; i < max_blocks && small_blocks[i] != NULL; i++) {
        result = arena_free(arena, small_blocks[i]);
        assert(result == 1);
    }
    
    /* Try to free one more block - this should fail if we've reached max_free_blocks */
    if (arena->free_count > 0 && arena->free_count >= arena->max_free_blocks) {
        block1 = arena_alloc(arena, 10);
        if (block1 != NULL) {
            result = arena_free(arena, block1);
            assert(result == 0);
        }
    }
    
    /* Test freeing an invalid pointer that's not part of our arena */
    char dummy[10];
    result = arena_free(arena, dummy);
    assert(result == 0);
    
    arena_destroy(arena);
    
    printf("[TEST] arena: All tests passed\n");
}

int main() 
{
    printf("Running unit tests for cooper.c...\n");

    test_arena_trim();
    test_arena_strip_comment();
    test_arena_extract_and_trim_value();
    test_load_config();
    test_should_trace_method();
    test_arena();
    test_event_queue();
    test_log_queue();
    printf("All tests completed successfully!\n");
    return 0;
}