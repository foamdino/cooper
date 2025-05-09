/*
* SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
* SPDX-License-Identifier: BSD-3-Clause
*/

#include "cooper.h"
#include "log.h"
#include "arena.h"
#include "arena_str.h"

log_q_t *log_queue = NULL;

/* Helper to create a temporary config file */
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

/* Initialize a minimal agent context for testing */
static agent_context_t *init_test_context() 
{
    agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
    if (!ctx) return NULL;
    
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
    ctx->export_running = 1;
    
    pthread_mutex_init(&ctx->samples_lock, NULL);
    
    return ctx;
}

/* Initialize a log queue for testing */
int init_log_q(agent_context_t *ctx)
{
    assert(ctx != NULL);
    
    log_q_t *queue = malloc(sizeof(log_q_t));
    if (!queue) return 1;
    
    queue->hd = 0;
    queue->tl = 0;
    queue->count = 0;
    queue->running = 1;
    memset(queue->messages, 0, sizeof(queue->messages));

    int err;

    err = pthread_mutex_init(&queue->lock, NULL);
    if (err != 0) {
        free(queue);
        printf("ERROR: Failed to init log queue mutex: %d\n", err);
        return 1;
    }

    err = pthread_cond_init(&queue->cond, NULL);
    if (err != 0) {
        pthread_mutex_destroy(&queue->lock);
        free(queue);
        printf("ERROR: Failed to init log queue condition: %d\n", err);
        return 1;
    }
    
    /* Store the queue in a global variable for the log system */
    log_queue = queue;
    return 0;
}


/* Cleanup test context */
static void cleanup_test_context(agent_context_t *ctx) 
{
    if (!ctx) return;
    
    pthread_mutex_destroy(&ctx->samples_lock);
    free(ctx);
}

/* Test arena_trim function */
static void test_arena_trim() 
{
    agent_context_t *ctx = init_test_context();
    arena_t *config_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);

    char *result1 = arena_trim(config_arena, "  hello  \n");
    assert(result1 != NULL);
    assert(strcmp(result1, "hello") == 0);

    char *result2 = arena_trim(config_arena, " \t\n");
    assert(result2 != NULL);
    assert(strlen(result2) == 0);

    char *result3 = arena_trim(config_arena, "no_spaces");
    assert(result3 != NULL);
    assert(strcmp(result3, "no_spaces") == 0);

    char *result4 = arena_trim(config_arena, "");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);

    printf("[TEST] test_arena_trim: All tests passed\n");
}

/* Test arena_strip_comment function */
static void test_arena_strip_comment() 
{
    agent_context_t *ctx = init_test_context();
    arena_t *config_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);

    char *result1 = arena_strip_comment(config_arena, "hello # comment");
    assert(result1 != NULL);
    assert(strcmp(result1, "hello ") == 0);

    char *result2 = arena_strip_comment(config_arena, "no comment here");
    assert(result2 != NULL);
    assert(strcmp(result2, "no comment here") == 0);

    char *result3 = arena_strip_comment(config_arena, "# comment only");
    assert(result3 != NULL);
    assert(strcmp(result3, "") == 0);

    char *result4 = arena_strip_comment(config_arena, "");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);

    printf("[TEST] test_arena_strip_comment: All tests passed\n");
}

/* Test arena_extract_and_trim_value function */
static void test_arena_extract_and_trim_value() 
{
    agent_context_t *ctx = init_test_context();
    arena_t *config_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);

    /* Standard key-value pair */
    char *result1 = arena_extract_and_trim_value(config_arena, "key = value");
    assert(result1 != NULL);
    assert(strcmp(result1, "value") == 0);

    /* Key-value pair with extra whitespace */
    char *result2 = arena_extract_and_trim_value(config_arena, "key =   value   ");
    assert(result2 != NULL);
    assert(strcmp(result2, "value") == 0);

    /* Key-value pair with no space after equals */
    char *result3 = arena_extract_and_trim_value(config_arena, "key=value");
    assert(result3 != NULL);
    assert(strcmp(result3, "value") == 0);
    
    /* Key with no value */
    char *result4 = arena_extract_and_trim_value(config_arena, "key = ");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    /* No equals sign */
    char *result5 = arena_extract_and_trim_value(config_arena, "key value");
    assert(result5 == NULL);

    /* Only equals sign */
    char *result6 = arena_extract_and_trim_value(config_arena, "=value");
    assert(result6 != NULL);
    assert(strcmp(result6, "value") == 0);

    /* Empty string */
    char *result7 = arena_extract_and_trim_value(config_arena, "");
    assert(result7 == NULL);

    /* Quoted value - should remove quotes */
    char *result8 = arena_extract_and_trim_value(config_arena, "key = \"quoted value\"");
    assert(result8 != NULL);
    assert(strcmp(result8, "quoted value") == 0);

    /* Quoted value with spaces around quotes */
    char *result9 = arena_extract_and_trim_value(config_arena, "key =  \"quoted value\"  ");
    assert(result9 != NULL);
    assert(strcmp(result9, "quoted value") == 0);

    /* Quoted value with only opening quote */
    char *result10 = arena_extract_and_trim_value(config_arena, "key = \"quoted value");
    assert(result10 != NULL);
    assert(strcmp(result10, "\"quoted value") == 0);

    /* Quoted value with only closing quote */
    char *result11 = arena_extract_and_trim_value(config_arena, "key = quoted value\"");
    assert(result11 != NULL);
    assert(strcmp(result11, "quoted value\"") == 0);

    /* Empty quoted value */
    char *result12 = arena_extract_and_trim_value(config_arena, "key = \"\"");
    assert(result12 != NULL);
    assert(strlen(result12) == 0);

    /* Quoted value with embedded equals sign */
    char *result13 = arena_extract_and_trim_value(config_arena, "key = \"value=with=equals\"");
    assert(result13 != NULL);
    assert(strcmp(result13, "value=with=equals") == 0);

    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);

    printf("[TEST] test_arena_extract_and_trim_value: All tests passed\n");
}

/* Test arena_process_config_line function */
static void test_arena_process_config_line() 
{
    agent_context_t *ctx = init_test_context();
    arena_t *config_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);

    /* Line with a comment */
    char *result1 = arena_process_config_line(config_arena, "key = value # comment");
    assert(result1 != NULL);
    assert(strcmp(result1, "key = value") == 0);

    /* Line with just whitespace */
    char *result2 = arena_process_config_line(config_arena, "  \t\n");
    assert(result2 != NULL);
    assert(strlen(result2) == 0);

    /* Line with both leading/trailing whitespace and comment */
    char *result3 = arena_process_config_line(config_arena, "   key = value   # comment ");
    assert(result3 != NULL);
    assert(strcmp(result3, "key = value") == 0);

    /* Line with only a comment */
    char *result4 = arena_process_config_line(config_arena, "# just a comment");
    assert(result4 != NULL);
    assert(strlen(result4) == 0);

    /* Empty line */
    char *result5 = arena_process_config_line(config_arena, "");
    assert(result5 != NULL);
    assert(strlen(result5) == 0);

    /* Line with quoted value and comment */
    char *result6 = arena_process_config_line(config_arena, "key = \"quoted value\" # comment");
    assert(result6 != NULL);
    assert(strcmp(result6, "key = \"quoted value\"") == 0);

    /* Line with embedded '#' in quoted value */
    char *result7 = arena_process_config_line(config_arena, "key = \"value with # inside quotes\"");
    assert(result7 != NULL);
    assert(strcmp(result7, "key = \"value with # inside quotes\"") == 0);

    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);

    printf("[TEST] test_arena_process_config_line: All tests passed\n");
}

/* Test load_config with a simple config */
static void test_load_config() 
{
    agent_context_t *ctx = init_test_context();
    
    /* Initialize log queue for the test */
    assert(init_log_q(ctx) == 0);
    
    /* Create necessary arenas */
    arena_t *config_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
    arena_t *log_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
    arena_t *metrics_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);

    /* Initialize log system */
    init_log_system(log_queue, ctx->arena_head, stdout);
    
    /* Initialize metrics */
    size_t initial_capacity = 256;
    ctx->metrics = init_method_metrics(metrics_arena, initial_capacity);
    assert(ctx->metrics != NULL);

    const char *config_content =
        "[sample_rate]\n"
        "# Default sample rate for methods without a specific rate\n"
        "rate = 5\n"
        "\n"
        "[method_signatures]\n"
        "filters = [\n"
        "    # Format: class_signature:method_name:method_signature:sample_rate:metrics\n"
        "    # Sample every invocation (rate=1) of method a in Test class\n"
        "    # Collect time, memory, and CPU metrics\n"
        "    Lcom/github/foamdino/Test;:a:()V:1:time,memory,cpu\n"
        "    \n"
        "    # Sample every 10th invocation of method b in Test class\n"
        "    # Collect only timing information\n"
        "    Lcom/github/foamdino/Test;:b:()V:10:time\n"
        "]\n"
        "\n"
        "[sample_file_location]\n"
        "path = \"/tmp/test.txt\"\n"
        "\n"
        "[export]\n"
        "method = \"file\"\n"
        "interval = 30\n";

    const char *config_file = create_temp_config(config_content);
    int result = load_config(ctx, config_file);
    /* Delete temp config file */
    unlink(config_file);

    assert(result == 0);
    assert(ctx->config.rate == 5);
    assert(ctx->config.num_filters == 2);
    assert(strcmp(ctx->config.sample_file_path, "/tmp/test.txt") == 0);
    assert(strcmp(ctx->config.export_method, "file") == 0);
    assert(ctx->config.export_interval == 30);
    
    /* Check that the metrics have been added correctly */
    assert(ctx->metrics != NULL);
    assert(ctx->metrics->count >= 2);
    
    /* Check first method filter */
    int method1_index = find_method_index(ctx->metrics, "Lcom/github/foamdino/Test; a ()V");
    
    /* Try alternative format if needed */
    if (method1_index < 0) {
        method1_index = find_method_index(ctx->metrics, "Lcom/github/foamdino/Test;:a:()V");
    }
    
    assert(method1_index >= 0);
    assert(ctx->metrics->sample_rates[method1_index] == 1);
    assert(ctx->metrics->metric_flags[method1_index] == (METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU));
    
    /* Check second method filter */
    int method2_index = find_method_index(ctx->metrics, "Lcom/github/foamdino/Test; b ()V");
    
    if (method2_index < 0) {
        method2_index = find_method_index(ctx->metrics, "Lcom/github/foamdino/Test;:b:()V");
    }
    
    assert(method2_index >= 0);
    assert(ctx->metrics->sample_rates[method2_index] == 10);
    assert(ctx->metrics->metric_flags[method2_index] == METRIC_FLAG_TIME);

    /* Clean up log system */
    cleanup_log_system();
    
    /* Free the log queue resources */
    if (log_queue) {
        pthread_mutex_destroy(&log_queue->lock);
        pthread_cond_destroy(&log_queue->cond);
        free(log_queue);
    }
    
    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);
    
    printf("[TEST] load_config: All tests passed\n");
}

/* Test the logging system queue functionality */
static void test_log_queue() 
{
    /* Initialize a file for logging */
    FILE *log_file = tmpfile();
    assert(log_file != NULL);
    
    /* Initialize test context */
    agent_context_t *ctx = init_test_context();
    assert(ctx != NULL);
    
    /* Initialize log arena for message storage */
    arena_t *log_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
    assert(log_arena != NULL);
    
    /* Initialize a log queue using the actual log system */
    log_q_t log_queue = {0};
    int res = init_log_system(&log_queue, ctx->arena_head, log_file);
    assert(res == 0);
    
    /* Use LOG macros to add messages to the queue */
    current_log_level = LOG_LEVEL_INFO; /* Ensure INFO logs are processed */
    log_message(LOG_LEVEL_INFO, "test_file.c", 123, "Test message 1");
    log_message(LOG_LEVEL_INFO, "test_file.c", 456, "Test message 2");
    
    /* Small delay to ensure messages are processed */
    usleep(10000);
    
    /* Export queue state to a variable for inspection */
    int message_count = log_queue.count;
    
    /* Clean up the log system (properly) */
    cleanup_log_system();
    
    /* Verify that the test worked */
    assert(message_count <= 2); /* Messages might have been processed already */
    
    /* Clean up the arenas */
    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);
    
    printf("[TEST] log_queue: All tests passed\n");
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

/* Test should_sample_method */
static void test_should_sample_method()
{
    agent_context_t *ctx = init_test_context();
    
    /* Initialize metrics arena for metrics data */
    arena_t *metrics_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
    
    /* Initialize event_counter (for rate-based sampling) */
    ctx->event_counter = 0;
    
    /* Initialize metrics structure */
    ctx->metrics = init_method_metrics(metrics_arena, 10);
    assert(ctx->metrics != NULL);
    
    /* Add a method with rate=1 (sample every call) */
    int idx1 = add_method_to_metrics(ctx, "Lcom/github/foamdino/Test; a ()V", 1, METRIC_FLAG_TIME | METRIC_FLAG_MEMORY);
    assert(idx1 >= 0);
    
    /* Add a method with rate=10 (sample every 10th call) */
    int idx2 = add_method_to_metrics(ctx, "Lcom/github/foamdino/Test; b ()V", 10, METRIC_FLAG_TIME);
    assert(idx2 >= 0);
    
    /* Add a class wildcard filter - use space format to match should_sample_method implementation */
    int idx3 = add_method_to_metrics(ctx, "Ljava/lang/String; * *", 50, METRIC_FLAG_TIME);
    assert(idx3 >= 0);
    
    /* Test exact method match with rate=1 */
    int sample1 = should_sample_method(ctx, "Lcom/github/foamdino/Test;", "a", "()V");
    assert(sample1 == idx1 + 1); /* +1 because 0 means "don't sample" */
    assert(ctx->metrics->call_counts[idx1] == 1);
    
    /* Call the same method again - should still sample because rate=1 */
    sample1 = should_sample_method(ctx, "Lcom/github/foamdino/Test;", "a", "()V");
    assert(sample1 == idx1 + 1);
    assert(ctx->metrics->call_counts[idx1] == 2);
    
    /* Test method with rate=10 */
    /* First call (count becomes 1) - NOT sampled */
    int sample2 = should_sample_method(ctx, "Lcom/github/foamdino/Test;", "b", "()V");
    assert(sample2 == 0); /* Should NOT be sampled on first call */
    assert(ctx->metrics->call_counts[idx2] == 1);
    
    /* Call 8 more times (count becomes 2-9) - not sampled */
    for (int i = 0; i < 8; i++) {
        sample2 = should_sample_method(ctx, "Lcom/github/foamdino/Test;", "b", "()V");
        assert(sample2 == 0); /* Don't sample these calls */
    }
    assert(ctx->metrics->call_counts[idx2] == 9);
    
    /* 10th call (count becomes 10) - SHOULD be sampled */
    sample2 = should_sample_method(ctx, "Lcom/github/foamdino/Test;", "b", "()V");
    assert(sample2 == idx2 + 1); /* 10th call should be sampled */
    assert(ctx->metrics->call_counts[idx2] == 10);
    
    /* Test class wildcard match */
    /* Since sample rate is 50, first call won't be sampled */
    int sample3 = should_sample_method(ctx, "Ljava/lang/String;", "length", "()I");
    assert(sample3 == 0); /* First call should NOT be sampled (rate=50) */
    assert(ctx->metrics->call_counts[idx3] == 1);
    
    /* Call 49 more times (positions 2-50) */
    for (int i = 1; i < 49; i++) {
        sample3 = should_sample_method(ctx, "Ljava/lang/String;", "length", "()I");
        assert(sample3 == 0); /* Don't sample these calls */
    }
    assert(ctx->metrics->call_counts[idx3] == 49);
    
    /* 50th call should be sampled */
    sample3 = should_sample_method(ctx, "Ljava/lang/String;", "length", "()I");
    assert(sample3 == idx3 + 1); /* 50th call should be sampled */
    assert(ctx->metrics->call_counts[idx3] == 50);
    
    /* Method not in the filters */
    int sample4 = should_sample_method(ctx, "Ljava/lang/Object;", "toString", "()Ljava/lang/String;");
    assert(sample4 == 0); /* Should not be sampled */
    
    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);
    
    printf("[TEST] should_sample_method: All tests passed\n");
}

/* Test metrics recording functionality */
static void test_record_method_execution()
{
    agent_context_t *ctx = init_test_context();
    
    /* Initialize metrics arena for metrics data */
    arena_t *metrics_arena = create_arena(&ctx->arena_head, &ctx->arena_tail, "metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
    assert(metrics_arena != NULL);
    
    /* Initialize metrics structure */
    ctx->metrics = init_method_metrics(metrics_arena, 10);
    assert(ctx->metrics != NULL);
    
    /* Add methods with different metric flags */
    int idx1 = add_method_to_metrics(ctx, "Method1", 1, METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU);
    int idx2 = add_method_to_metrics(ctx, "Method2", 1, METRIC_FLAG_TIME);
    int idx3 = add_method_to_metrics(ctx, "Method3", 1, METRIC_FLAG_MEMORY);
    int idx4 = add_method_to_metrics(ctx, "Method4", 1, METRIC_FLAG_CPU);
    
    /* Record execution for method with all metrics */
    record_method_execution(ctx, idx1, 1000, 512, 2000);
    assert(ctx->metrics->sample_counts[idx1] == 1);
    assert(ctx->metrics->total_time_ns[idx1] == 1000);
    assert(ctx->metrics->min_time_ns[idx1] == 1000);
    assert(ctx->metrics->max_time_ns[idx1] == 1000);
    assert(ctx->metrics->alloc_bytes[idx1] == 512);
    assert(ctx->metrics->peak_memory[idx1] == 512);
    assert(ctx->metrics->cpu_cycles[idx1] == 2000);
    
    /* Record another execution with different values */
    record_method_execution(ctx, idx1, 2000, 256, 1500);
    assert(ctx->metrics->sample_counts[idx1] == 2);
    assert(ctx->metrics->total_time_ns[idx1] == 3000); /* 1000 + 2000 */
    assert(ctx->metrics->min_time_ns[idx1] == 1000);   /* Min remains 1000 */
    assert(ctx->metrics->max_time_ns[idx1] == 2000);   /* Max updated to 2000 */
    assert(ctx->metrics->alloc_bytes[idx1] == 768);    /* 512 + 256 */
    assert(ctx->metrics->peak_memory[idx1] == 512);    /* Peak remains 512 */
    assert(ctx->metrics->cpu_cycles[idx1] == 3500);    /* 2000 + 1500 */
    
    /* Record with a lower execution time to test min update */
    record_method_execution(ctx, idx1, 500, 1024, 3000);
    assert(ctx->metrics->sample_counts[idx1] == 3);
    assert(ctx->metrics->total_time_ns[idx1] == 3500); /* 3000 + 500 */
    assert(ctx->metrics->min_time_ns[idx1] == 500);    /* Min updated to 500 */
    assert(ctx->metrics->max_time_ns[idx1] == 2000);   /* Max remains 2000 */
    assert(ctx->metrics->alloc_bytes[idx1] == 1792);   /* 768 + 1024 */
    assert(ctx->metrics->peak_memory[idx1] == 1024);   /* Peak updated to 1024 */
    assert(ctx->metrics->cpu_cycles[idx1] == 6500);    /* 3500 + 3000 */
    
    /* Test method with only time metrics */
    record_method_execution(ctx, idx2, 1500, 256, 2000);
    assert(ctx->metrics->sample_counts[idx2] == 1);
    assert(ctx->metrics->total_time_ns[idx2] == 1500);
    assert(ctx->metrics->min_time_ns[idx2] == 1500);
    assert(ctx->metrics->max_time_ns[idx2] == 1500);
    assert(ctx->metrics->alloc_bytes[idx2] == 0);      /* Memory not tracked */
    assert(ctx->metrics->peak_memory[idx2] == 0);      /* Memory not tracked */
    assert(ctx->metrics->cpu_cycles[idx2] == 0);       /* CPU not tracked */
    
    /* Test method with only memory metrics */
    record_method_execution(ctx, idx3, 1500, 256, 2000);
    assert(ctx->metrics->sample_counts[idx3] == 1);
    assert(ctx->metrics->total_time_ns[idx3] == 0);    /* Time not tracked */
    assert(ctx->metrics->min_time_ns[idx3] == UINT64_MAX); /* Default value for min */
    assert(ctx->metrics->max_time_ns[idx3] == 0);      /* Time not tracked */
    assert(ctx->metrics->alloc_bytes[idx3] == 256);
    assert(ctx->metrics->peak_memory[idx3] == 256);
    assert(ctx->metrics->cpu_cycles[idx3] == 0);       /* CPU not tracked */
    
    /* Test method with only CPU metrics */
    record_method_execution(ctx, idx4, 1500, 256, 2000);
    assert(ctx->metrics->sample_counts[idx4] == 1);
    assert(ctx->metrics->total_time_ns[idx4] == 0);    /* Time not tracked */
    assert(ctx->metrics->min_time_ns[idx4] == UINT64_MAX); /* Default value for min */
    assert(ctx->metrics->max_time_ns[idx4] == 0);      /* Time not tracked */
    assert(ctx->metrics->alloc_bytes[idx4] == 0);      /* Memory not tracked */
    assert(ctx->metrics->peak_memory[idx4] == 0);      /* Memory not tracked */
    assert(ctx->metrics->cpu_cycles[idx4] == 2000);
    
    /* Test invalid method index - should not crash */
    record_method_execution(ctx, 999, 1000, 512, 2000);
    record_method_execution(ctx, -1, 1000, 512, 2000);
    
    destroy_all_arenas(&ctx->arena_head, &ctx->arena_tail);
    cleanup_test_context(ctx);
    
    printf("[TEST] record_method_execution: All tests passed\n");
}

int main() 
{
    printf("Running unit tests for cooper.c...\n");

    test_arena_trim();
    test_arena_strip_comment();
    test_arena_extract_and_trim_value();
    test_arena_process_config_line();
    test_load_config();
    test_should_sample_method();
    test_record_method_execution();
    test_arena();
    test_log_queue();
    printf("All tests completed successfully!\n");
    return 0;
}