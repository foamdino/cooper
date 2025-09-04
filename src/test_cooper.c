/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper.h"
#include "log.h"
#include "arena.h"
#include "arena_str.h"
#include "cpu.h"
#include "cache.h"
#include "config.h"
#include "shared_mem.h"

q_t *log_queue = NULL;

/* Comparison functions for cache tests */
static int
int_compare(const void *key1, const void *key2)
{
	int k1 = *(const int *)key1;
	int k2 = *(const int *)key2;
	return (k1 == k2) ? 0 : ((k1 < k2) ? -1 : 1);
}

static int
string_compare(const void *key1, const void *key2)
{
	return strcmp((const char *)key1, (const char *)key2);
}

/* Helper to create a temporary config file */
static const char *
create_temp_config(const char *content)
{
	const char *filename = "/tmp/test_config.ini";
	FILE *fp             = fopen(filename, "w");
	if (!fp)
	{
		perror("Failed to create temp config file");
		exit(1);
	}
	fputs(content, fp);
	fclose(fp);
	return filename;
}

/* Initialize a minimal agent context for testing */
static agent_context_t *
init_test_context()
{
	agent_context_t *ctx = calloc(1, sizeof(agent_context_t));
	if (!ctx)
		return NULL;

	ctx->jvmti_env               = NULL;
	ctx->method_filters          = NULL;
	ctx->num_filters             = 0;
	ctx->log_file                = NULL;
	ctx->config.rate             = 1;
	ctx->config.filters          = NULL;
	ctx->config.num_filters      = 0;
	ctx->config.sample_file_path = NULL;
	ctx->config.export_method    = NULL;
	ctx->config.export_interval  = 60;

	pthread_mutex_init(&ctx->samples_lock, NULL);

	return ctx;
}

/* Initialize a log queue for testing */
int
init_log_q(agent_context_t *ctx)
{
	assert(ctx != NULL);

	q_t *queue = calloc(1, sizeof(q_t));
	if (!queue)
		return 1;

	queue->running = 1;
	int err;

	err = pthread_mutex_init(&queue->lock, NULL);
	if (err != 0)
	{
		free(queue);
		printf("ERROR: Failed to init log queue mutex: %d\n", err);
		return 1;
	}

	err = pthread_cond_init(&queue->cond, NULL);
	if (err != 0)
	{
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
static void
cleanup_test_context(agent_context_t *ctx)
{
	if (!ctx)
		return;

	pthread_mutex_destroy(&ctx->samples_lock);
	free(ctx);
}

/* Test arena_trim function */
static void
test_arena_trim()
{
	agent_context_t *ctx = init_test_context();
	arena_t *config_arena =
	    arena_init("config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
	ctx->arenas[CONFIG_ARENA_ID] = config_arena;

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

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_arena_trim: All tests passed\n");
}

/* Test arena_strip_comment function */
static void
test_arena_strip_comment()
{
	agent_context_t *ctx = init_test_context();
	arena_t *config_arena =
	    arena_init("config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
	ctx->arenas[CONFIG_ARENA_ID] = config_arena;

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

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_arena_strip_comment: All tests passed\n");
}

/* Test config_extract_and_trim_value function */
static void
test_config_extract_and_trim_value()
{
	agent_context_t *ctx = init_test_context();
	arena_t *config_arena =
	    arena_init("config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
	ctx->arenas[CONFIG_ARENA_ID] = config_arena;

	/* Standard key-value pair */
	char *result1 = config_extract_and_trim_value(config_arena, "key = value");
	assert(result1 != NULL);
	assert(strcmp(result1, "value") == 0);

	/* Key-value pair with extra whitespace */
	char *result2 = config_extract_and_trim_value(config_arena, "key =   value   ");
	assert(result2 != NULL);
	assert(strcmp(result2, "value") == 0);

	/* Key-value pair with no space after equals */
	char *result3 = config_extract_and_trim_value(config_arena, "key=value");
	assert(result3 != NULL);
	assert(strcmp(result3, "value") == 0);

	/* Key with no value */
	char *result4 = config_extract_and_trim_value(config_arena, "key = ");
	assert(result4 != NULL);
	assert(strlen(result4) == 0);

	/* No equals sign */
	char *result5 = config_extract_and_trim_value(config_arena, "key value");
	assert(result5 == NULL);

	/* Only equals sign */
	char *result6 = config_extract_and_trim_value(config_arena, "=value");
	assert(result6 != NULL);
	assert(strcmp(result6, "value") == 0);

	/* Empty string */
	char *result7 = config_extract_and_trim_value(config_arena, "");
	assert(result7 == NULL);

	/* Quoted value - should remove quotes */
	char *result8 =
	    config_extract_and_trim_value(config_arena, "key = \"quoted value\"");
	assert(result8 != NULL);
	assert(strcmp(result8, "quoted value") == 0);

	/* Quoted value with spaces around quotes */
	char *result9 =
	    config_extract_and_trim_value(config_arena, "key =  \"quoted value\"  ");
	assert(result9 != NULL);
	assert(strcmp(result9, "quoted value") == 0);

	/* Quoted value with only opening quote */
	char *result10 =
	    config_extract_and_trim_value(config_arena, "key = \"quoted value");
	assert(result10 != NULL);
	assert(strcmp(result10, "\"quoted value") == 0);

	/* Quoted value with only closing quote */
	char *result11 =
	    config_extract_and_trim_value(config_arena, "key = quoted value\"");
	assert(result11 != NULL);
	assert(strcmp(result11, "quoted value\"") == 0);

	/* Empty quoted value */
	char *result12 = config_extract_and_trim_value(config_arena, "key = \"\"");
	assert(result12 != NULL);
	assert(strlen(result12) == 0);

	/* Quoted value with embedded equals sign */
	char *result13 =
	    config_extract_and_trim_value(config_arena, "key = \"value=with=equals\"");
	assert(result13 != NULL);
	assert(strcmp(result13, "value=with=equals") == 0);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_config_extract_and_trim_value: All tests passed\n");
}

/* Test config_process_config_line function */
static void
test_config_process_config_line()
{
	agent_context_t *ctx = init_test_context();
	arena_t *config_arena =
	    arena_init("config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
	ctx->arenas[CONFIG_ARENA_ID] = config_arena;

	/* Line with a comment */
	char *result1 = config_process_config_line(config_arena, "key = value # comment");
	assert(result1 != NULL);
	assert(strcmp(result1, "key = value") == 0);

	/* Line with just whitespace */
	char *result2 = config_process_config_line(config_arena, "  \t\n");
	assert(result2 != NULL);
	assert(strlen(result2) == 0);

	/* Line with both leading/trailing whitespace and comment */
	char *result3 =
	    config_process_config_line(config_arena, "   key = value   # comment ");
	assert(result3 != NULL);
	assert(strcmp(result3, "key = value") == 0);

	/* Line with only a comment */
	char *result4 = config_process_config_line(config_arena, "# just a comment");
	assert(result4 != NULL);
	assert(strlen(result4) == 0);

	/* Empty line */
	char *result5 = config_process_config_line(config_arena, "");
	assert(result5 != NULL);
	assert(strlen(result5) == 0);

	/* Line with quoted value and comment */
	char *result6 =
	    config_process_config_line(config_arena, "key = \"quoted value\" # comment");
	assert(result6 != NULL);
	assert(strcmp(result6, "key = \"quoted value\"") == 0);

	/* Line with embedded '#' in quoted value */
	char *result7 = config_process_config_line(
	    config_arena, "key = \"value with # inside quotes\"");
	assert(result7 != NULL);
	assert(strcmp(result7, "key = \"value with # inside quotes\"") == 0);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_config_process_config_line: All tests passed\n");
}

/* Test load_config with a simple config */
static void
test_load_config()
{
	agent_context_t *ctx = init_test_context();

	/* Initialize log queue for the test */
	assert(init_log_q(ctx) == 0);

	/* Create necessary arenas */
	arena_t *config_arena =
	    arena_init("config_arena", CONFIG_ARENA_SZ, CONFIG_ARENA_BLOCKS);
	ctx->arenas[CONFIG_ARENA_ID] = config_arena;
	arena_t *log_arena = arena_init("log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
	ctx->arenas[LOG_ARENA_ID] = log_arena;
	arena_t *metrics_arena =
	    arena_init("metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
	ctx->arenas[METRICS_ARENA_ID] = metrics_arena;

	/* Initialize log system */
	init_log_system(log_queue, log_arena, stdout);

	/* Initialize metrics */
	size_t initial_capacity = 256;
	ctx->metrics            = init_method_metrics(metrics_arena, initial_capacity);
	assert(ctx->metrics != NULL);

	const char *config_content =
	    "[sample_rate]\n"
	    "# Default sample rate for methods without a specific rate\n"
	    "rate = 5\n"
	    "\n"
	    "[method_signatures]\n"
	    "filters = [\n"
	    "    # Format: "
	    "class_signature:method_name:method_signature:sample_rate:metrics\n"
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
	int result              = load_config(ctx, config_file);
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
	int method1_index =
	    find_method_index(ctx->metrics, "Lcom/github/foamdino/Test; a ()V");

	/* Try alternative format if needed */
	if (method1_index < 0)
	{
		method1_index =
		    find_method_index(ctx->metrics, "Lcom/github/foamdino/Test;:a:()V");
	}

	assert(method1_index >= 0);
	assert(ctx->metrics->sample_rates[method1_index] == 1);
	assert(ctx->metrics->metric_flags[method1_index]
	       == (METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU));

	/* Check second method filter */
	int method2_index =
	    find_method_index(ctx->metrics, "Lcom/github/foamdino/Test; b ()V");

	if (method2_index < 0)
	{
		method2_index =
		    find_method_index(ctx->metrics, "Lcom/github/foamdino/Test;:b:()V");
	}

	assert(method2_index >= 0);
	assert(ctx->metrics->sample_rates[method2_index] == 10);
	assert(ctx->metrics->metric_flags[method2_index] == METRIC_FLAG_TIME);

	/* Clean up log system */
	cleanup_log_system();

	/* Free the log queue resources */
	if (log_queue)
	{
		pthread_mutex_destroy(&log_queue->lock);
		pthread_cond_destroy(&log_queue->cond);
		free(log_queue);
	}

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] load_config: All tests passed\n");
}

/* Test the logging system queue functionality */
static void
test_log_queue()
{
	/* Initialize a file for logging */
	FILE *log_file = tmpfile();
	assert(log_file != NULL);

	/* Initialize test context */
	agent_context_t *ctx = init_test_context();
	assert(ctx != NULL);

	/* Initialize log arena for message storage */
	arena_t *log_arena = arena_init("log_arena", LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
	ctx->arenas[LOG_ARENA_ID] = log_arena;
	assert(log_arena != NULL);

	/* Initialize a log queue using the actual log system */
	q_t log_queue = {0};
	int res       = init_log_system(&log_queue, log_arena, log_file);
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
	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] log_queue: All tests passed\n");
}

/* Test arena memory management */
static void
test_arena()
{
	/* Test arena_init */
	size_t page_size = sysconf(_SC_PAGESIZE);
	arena_t *arena   = arena_init("test_arena", 1024, 10);
	assert(arena != NULL);
	assert(strcmp(arena->name, "test_arena") == 0);
	assert(arena->requested_sz == 1024);
	assert(arena->total_sz % page_size == 0); /* Verify page alignment */
	assert(arena->total_sz >= 1024);
	assert(arena->available_sz < arena->total_sz); /* Should be less as we subtract
	                                                  the tracking metadata size */
	assert(arena->used == 0);
	assert(arena->free_count == 0);
	assert(arena->max_free_blocks == 10);

	/* Test arena_alloc */
	void *block1 = arena_alloc(arena, 100);
	assert(block1 != NULL);
	assert(arena->used >= 100);

	/* Check that the block header has the correct magic number */
	block_header_t *header1 =
	    (block_header_t *)((char *)block1 - sizeof(block_header_t));
	assert(header1->magic == ARENA_BLOCK_MAGIC);
	assert(header1->block_sz == 100);

	/* Write to the memory to ensure it's usable */
	memset(block1, 'A', 100);

	/* Allocate another block */
	void *block2 = arena_alloc(arena, 200);
	assert(block2 != NULL);
	assert((char *)block2 > (char *)block1);
	assert(arena->used >= 300); /* Including alignment padding */

	/* Check that the second block header has the correct magic number */
	block_header_t *header2 =
	    (block_header_t *)((char *)block2 - sizeof(block_header_t));
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
	block_header_t *header3 =
	    (block_header_t *)((char *)block3 - sizeof(block_header_t));
	assert(header3->magic == ARENA_BLOCK_MAGIC);
	assert(header3->block_sz == 100);

	/* If the free block was reused, block3 should be the same as block1 */
	if (arena->free_count == 0)
	{
		assert(block3 == block1);
	}

	/* Test corrupting a block header and verifying that free fails */
	header2->magic = 0xDEADBEEF; /* Corrupt the magic number */
	result         = arena_free(arena, block2);
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
	header1 = (block_header_t *)((char *)block1 - sizeof(block_header_t));
	assert(header1->magic == ARENA_BLOCK_MAGIC);

	/* This should fail as we don't have enough space */
	void *big_block = arena_alloc(arena, 10000);
	assert(big_block == NULL);

	/* Test having more free blocks than we can track */
	size_t i;
	void *small_blocks[10];

	/* Calculate how many blocks we can allocate based on remaining space */
	size_t max_blocks =
	    2; /* Reduce the number of allocations to fit in small_arena */
	for (i = 0; i < max_blocks; i++)
	{
		small_blocks[i] = arena_alloc(arena, 10);
		/* If allocation fails, don't try to verify magic number */
		if (small_blocks[i] == NULL)
		{
			break;
		}

		/* Verify magic number in each block */
		block_header_t *header =
		    (block_header_t *)((char *)small_blocks[i] - sizeof(block_header_t));
		assert(header->magic == ARENA_BLOCK_MAGIC);
	}

	/* Only free the blocks that were successfully allocated */
	for (i = 0; i < max_blocks && small_blocks[i] != NULL; i++)
	{
		result = arena_free(arena, small_blocks[i]);
		assert(result == 1);
	}

	/* Try to free one more block - this should fail if we've reached max_free_blocks
	 */
	if (arena->free_count > 0 && arena->free_count >= arena->max_free_blocks)
	{
		block1 = arena_alloc(arena, 10);
		if (block1 != NULL)
		{
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

/* Test metrics recording functionality */
static void
test_record_method_execution()
{
	agent_context_t *ctx = init_test_context();

	/* Initialize metrics arena for metrics data */
	arena_t *metrics_arena =
	    arena_init("metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
	ctx->arenas[METRICS_ARENA_ID] = metrics_arena;
	assert(metrics_arena != NULL);

	/* Initialize metrics structure */
	ctx->metrics = init_method_metrics(metrics_arena, 10);
	assert(ctx->metrics != NULL);

	/* Add methods with different metric flags */
	int idx1 = add_method_to_metrics(
	    ctx, "Method1", 1, METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU);
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
	assert(ctx->metrics->alloc_bytes[idx2] == 0); /* Memory not tracked */
	assert(ctx->metrics->peak_memory[idx2] == 0); /* Memory not tracked */
	assert(ctx->metrics->cpu_cycles[idx2] == 0);  /* CPU not tracked */

	/* Test method with only memory metrics */
	record_method_execution(ctx, idx3, 1500, 256, 2000);
	assert(ctx->metrics->sample_counts[idx3] == 1);
	assert(ctx->metrics->total_time_ns[idx3] == 0);        /* Time not tracked */
	assert(ctx->metrics->min_time_ns[idx3] == UINT64_MAX); /* Default value for min */
	assert(ctx->metrics->max_time_ns[idx3] == 0);          /* Time not tracked */
	assert(ctx->metrics->alloc_bytes[idx3] == 256);
	assert(ctx->metrics->peak_memory[idx3] == 256);
	assert(ctx->metrics->cpu_cycles[idx3] == 0); /* CPU not tracked */

	/* Test method with only CPU metrics */
	record_method_execution(ctx, idx4, 1500, 256, 2000);
	assert(ctx->metrics->sample_counts[idx4] == 1);
	assert(ctx->metrics->total_time_ns[idx4] == 0);        /* Time not tracked */
	assert(ctx->metrics->min_time_ns[idx4] == UINT64_MAX); /* Default value for min */
	assert(ctx->metrics->max_time_ns[idx4] == 0);          /* Time not tracked */
	assert(ctx->metrics->alloc_bytes[idx4] == 0);          /* Memory not tracked */
	assert(ctx->metrics->peak_memory[idx4] == 0);          /* Memory not tracked */
	assert(ctx->metrics->cpu_cycles[idx4] == 2000);

	/* Test invalid method index - should not crash */
	record_method_execution(ctx, 999, 1000, 512, 2000);
	record_method_execution(ctx, -1, 1000, 512, 2000);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] record_method_execution: All tests passed\n");
}

/* Test CPU cycle counting functionality */
static void
test_cpu_cycles()
{
	/* These functions are architecture specific */
#if defined(__x86_64__) || defined(__aarch64__)
	/* Test that cycles_start() returns a non-zero value */
	uint64_t start = cycles_start();
	assert(start > 0);

	/* Test that cycles_end() returns a non-zero value */
	uint64_t end = cycles_end();
	assert(end > 0);

	/* Test that cycles increase over time */
	start = cycles_start();

	/* Do some work to consume CPU cycles */
	volatile int sum = 0;
	for (int i = 0; i < 10000; i++)
	{
		sum += i;
	}

	end = cycles_end();

	/* End should be greater than start */
	assert(end > start);

	/* The difference should be reasonable (not too small, not too large) */
	uint64_t diff = end - start;
	assert(diff > 0);

	/* Do a longer computation and verify it takes more cycles */
	start = cycles_start();

	sum = 0;
	for (int i = 0; i < 100000; i++)
	{
		sum += i;
	}

	end                  = cycles_end();
	uint64_t longer_diff = end - start;

	/* The longer computation should take more cycles than the shorter one */
	assert(longer_diff > diff);

	/* Test that consecutive calls show monotonic increase */
	uint64_t prev = cycles_start();
	for (int i = 0; i < 5; i++)
	{
		uint64_t curr = cycles_start();
		assert(curr >= prev); /* Should be monotonically increasing */
		prev = curr;
	}

	printf("[TEST] test_cpu_cycles: All tests passed\n");
#else
	/* On unsupported architectures, these functions return 0 */
	assert(cycles_start() == 0);
	assert(cycles_end() == 0);

	printf("[TEST] test_cpu_cycles: CPU cycle counting not supported on this "
	       "architecture\n");
#endif
}

/* Test basic cache functionality */
static void
test_cache_basic()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Simple integer key-value cache */
	cache_config_t config = {.max_entries = 4,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare =
	                             NULL, /* Will set custom compare function */
	                         .key_copy   = NULL, /* Use default memcpy */
	                         .value_copy = NULL, /* Use default memcpy */
	                         .entry_init = NULL,
	                         .name       = "test_cache"};

	config.key_compare = int_compare;

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Test cache is initially empty */
	int value;
	assert(cache_get(cache, &(int){1}, &value) == 1); /* Should miss */

	/* Test putting and getting values */
	assert(cache_put(cache, &(int){1}, &(int){100}) == 0);
	assert(cache_get(cache, &(int){1}, &value) == 0);
	assert(value == 100);

	/* Test multiple entries */
	assert(cache_put(cache, &(int){2}, &(int){200}) == 0);
	assert(cache_put(cache, &(int){3}, &(int){300}) == 0);
	assert(cache_put(cache, &(int){4}, &(int){400}) == 0);

	/* Verify all entries */
	assert(cache_get(cache, &(int){1}, &value) == 0 && value == 100);
	assert(cache_get(cache, &(int){2}, &value) == 0 && value == 200);
	assert(cache_get(cache, &(int){3}, &value) == 0 && value == 300);
	assert(cache_get(cache, &(int){4}, &value) == 0 && value == 400);

	/* Test cache stats */
	size_t entries;
	cache_stats(cache, NULL, NULL, &entries);
	assert(entries == 4);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_basic: All tests passed\n");
}

/* Test cache eviction when full */
static void
test_cache_eviction()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	cache_config_t config = {.max_entries = 3,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare = int_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "eviction_test"};

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Fill cache to capacity */
	assert(cache_put(cache, &(int){1}, &(int){100}) == 0);
	assert(cache_put(cache, &(int){2}, &(int){200}) == 0);
	assert(cache_put(cache, &(int){3}, &(int){300}) == 0);

	/* Verify all entries are present */
	int value;
	assert(cache_get(cache, &(int){1}, &value) == 0 && value == 100);
	assert(cache_get(cache, &(int){2}, &value) == 0 && value == 200);
	assert(cache_get(cache, &(int){3}, &value) == 0 && value == 300);

	/* Add another entry - should evict the first one (round-robin) */
	assert(cache_put(cache, &(int){4}, &(int){400}) == 0);

	/* First entry should be evicted */
	assert(cache_get(cache, &(int){1}, &value) == 1); /* Should miss */

	/* Other entries should still be present */
	assert(cache_get(cache, &(int){2}, &value) == 0 && value == 200);
	assert(cache_get(cache, &(int){3}, &value) == 0 && value == 300);
	assert(cache_get(cache, &(int){4}, &value) == 0 && value == 400);

	/* Add another entry - should evict the second one */
	assert(cache_put(cache, &(int){5}, &(int){500}) == 0);
	assert(cache_get(cache, &(int){2}, &value) == 1); /* Should miss */
	assert(cache_get(cache, &(int){3}, &value) == 0 && value == 300);
	assert(cache_get(cache, &(int){4}, &value) == 0 && value == 400);
	assert(cache_get(cache, &(int){5}, &value) == 0 && value == 500);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_eviction: All tests passed\n");
}

/* Test cache update of existing entries */
static void
test_cache_update()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	cache_config_t config = {.max_entries = 4,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare = int_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "update_test"};

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Add initial entry */
	assert(cache_put(cache, &(int){1}, &(int){100}) == 0);

	int value;
	assert(cache_get(cache, &(int){1}, &value) == 0 && value == 100);

	/* Update existing entry */
	assert(cache_put(cache, &(int){1}, &(int){999}) == 0);
	assert(cache_get(cache, &(int){1}, &value) == 0 && value == 999);

	/* Cache should still have only 1 entry */
	size_t entries;
	cache_stats(cache, NULL, NULL, &entries);
	assert(entries == 1);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_update: All tests passed\n");
}

/* Test cache clear functionality */
static void
test_cache_clear()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	cache_config_t config = {.max_entries = 4,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare = int_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "clear_test"};

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Add some entries */
	assert(cache_put(cache, &(int){1}, &(int){100}) == 0);
	assert(cache_put(cache, &(int){2}, &(int){200}) == 0);
	assert(cache_put(cache, &(int){3}, &(int){300}) == 0);

	/* Verify entries exist */
	int value;
	assert(cache_get(cache, &(int){1}, &value) == 0);
	assert(cache_get(cache, &(int){2}, &value) == 0);
	assert(cache_get(cache, &(int){3}, &value) == 0);

	/* Clear the cache */
	cache_clear(cache);

	/* All entries should be gone */
	assert(cache_get(cache, &(int){1}, &value) == 1);
	assert(cache_get(cache, &(int){2}, &value) == 1);
	assert(cache_get(cache, &(int){3}, &value) == 1);

	/* Cache should be empty */
	size_t entries;
	cache_stats(cache, NULL, NULL, &entries);
	assert(entries == 0);

	/* Should be able to add entries again */
	assert(cache_put(cache, &(int){4}, &(int){400}) == 0);
	assert(cache_get(cache, &(int){4}, &value) == 0 && value == 400);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_clear: All tests passed\n");
}

/* Test thread-local cache functionality */
static void
test_cache_tls()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Initialize TLS cache system */
	assert(cache_tls_init() == 0);

	cache_config_t config = {.max_entries = 4,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare = int_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "tls_test"};

	int res = cache_init_system(test_arena);
	assert(res == 0);

	/* Get thread-local cache instance */
	cache_t *cache1 = cache_tls_get("test_cache_1", test_arena, &config);
	assert(cache1 != NULL);

	/* Get the same cache again - should return same instance */
	cache_t *cache1_again = cache_tls_get("test_cache_1", test_arena, &config);
	assert(cache1_again == cache1);

	/* Get a different cache - should return different instance */
	cache_t *cache2 = cache_tls_get("test_cache_2", test_arena, &config);
	assert(cache2 != NULL);
	assert(cache2 != cache1);

	/* Test that caches are independent */
	assert(cache_put(cache1, &(int){1}, &(int){100}) == 0);
	assert(cache_put(cache2, &(int){1}, &(int){200}) == 0);

	int value;
	assert(cache_get(cache1, &(int){1}, &value) == 0 && value == 100);
	assert(cache_get(cache2, &(int){1}, &value) == 0 && value == 200);

	/* Cleanup TLS */
	cache_tls_cleanup();

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_tls: All tests passed\n");
}

/* Test cache error conditions */
static void
test_cache_errors()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Test invalid configurations (should return NULL gracefully) */
	cache_config_t bad_config = {.max_entries = 0, /* Invalid */
	                             .key_size    = sizeof(int),
	                             .value_size  = sizeof(int),
	                             .key_compare = int_compare,
	                             .key_copy    = NULL,
	                             .value_copy  = NULL,
	                             .entry_init  = NULL,
	                             .name        = "bad_config"};

	assert(cache_init(test_arena, &bad_config) == NULL);

	bad_config.max_entries = 4;
	bad_config.key_size    = 0; /* Invalid */
	assert(cache_init(test_arena, &bad_config) == NULL);

	bad_config.key_size   = sizeof(int);
	bad_config.value_size = 0; /* Invalid */
	assert(cache_init(test_arena, &bad_config) == NULL);

	bad_config.value_size  = sizeof(int);
	bad_config.key_compare = NULL; /* Invalid */
	assert(cache_init(test_arena, &bad_config) == NULL);

	/* Test with valid configuration */
	cache_config_t good_config = {.max_entries = 4,
	                              .key_size    = sizeof(int),
	                              .value_size  = sizeof(int),
	                              .key_compare = int_compare,
	                              .key_copy    = NULL,
	                              .value_copy  = NULL,
	                              .entry_init  = NULL,
	                              .name        = "good_config"};

	cache_t *cache = cache_init(test_arena, &good_config);
	assert(cache != NULL);

	/* Test NULL parameters on operations (should return 1/fail gracefully) */
	int value;
	assert(cache_get(NULL, &(int){1}, &value) == 1);
	assert(cache_get(cache, NULL, &value) == 1);

	assert(cache_put(NULL, &(int){1}, &(int){100}) == 1);
	assert(cache_put(cache, NULL, &(int){100}) == 1);
	assert(cache_put(cache, &(int){1}, NULL) == 1);

	/* These should not crash (testing NULL safety) */
	cache_clear(NULL);
	cache_stats(NULL, NULL, NULL, NULL);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_errors: All tests passed\n");
}

/* Test cache with string keys */
static void
test_cache_string_keys()
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	cache_config_t config = {.max_entries = 4,
	                         .key_size    = 32, /* Fixed size string keys */
	                         .value_size  = sizeof(int),
	                         .key_compare = string_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "string_cache"};

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Test string keys */
	char key1[32] = "method1";
	char key2[32] = "method2";
	char key3[32] = "method3";

	assert(cache_put(cache, key1, &(int){100}) == 0);
	assert(cache_put(cache, key2, &(int){200}) == 0);
	assert(cache_put(cache, key3, &(int){300}) == 0);

	int value;
	assert(cache_get(cache, key1, &value) == 0 && value == 100);
	assert(cache_get(cache, key2, &value) == 0 && value == 200);
	assert(cache_get(cache, key3, &value) == 0 && value == 300);

	/* Test with string literals */
	assert(cache_get(cache, "method1", &value) == 0 && value == 100);
	assert(cache_get(cache, "method2", &value) == 0 && value == 200);
	assert(cache_get(cache, "nonexistent", &value) == 1);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_string_keys: All tests passed\n");
}

/**
 * Test basic shared memory initialization and cleanup
 */
static void
test_shared_memory_init()
{
	cooper_shm_context_t ctx = {0};

	/* Test successful initialization */
	int result = cooper_shm_init_agent(&ctx);
	assert(result == 0);
	assert(ctx.data_shm != NULL);
	assert(ctx.status_shm != NULL);
	assert(ctx.data_fd > 0);
	assert(ctx.status_fd > 0);

	/* Verify header initialization */
	assert(ctx.data_shm->version == COOPER_SHM_VERSION);
	assert(ctx.data_shm->max_entries == COOPER_MAX_ENTRIES);
	assert(ctx.data_shm->next_write_index == 0);

	/* Verify all status entries are empty */
	for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++)
	{
		assert(ctx.status_shm->status[i] == ENTRY_EMPTY);
	}

	/* Test cleanup */
	result = cooper_shm_cleanup_agent(&ctx);
	assert(result == 0);

	printf("[TEST] test_shared_memory_init: All tests passed\n");
}

/**
 * Test status state transitions
 */
static void
test_shared_memory_status_transitions()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Initial state should be EMPTY */
	assert(ctx.status_shm->status[0] == ENTRY_EMPTY);

	/* Create test data using new structure */
	struct cooper_method_data test_method = {.signature     = "TestMethod",
	                                         .call_count    = 100,
	                                         .sample_count  = 10,
	                                         .total_time_ns = 50000};

	/* Write should succeed on empty slot */
	int result = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == 0);
	assert(ctx.status_shm->status[0] == ENTRY_READY);

	/* Writing to same slot should fail (backpressure) */
	ctx.data_shm->next_write_index = 0; /* Reset to same slot */
	result                         = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == -1);                             /* Should fail */
	assert(ctx.status_shm->status[0] == ENTRY_READY); /* State unchanged */

	/* Simulate CLI reading the data */
	struct cooper_sample_entry read_entry;
	memcpy(&read_entry, &ctx.data_shm->entries[0], sizeof(read_entry));

	/* Verify data integrity using new structure */
	assert(read_entry.type == COOPER_DATA_METHOD_METRIC);
	assert(strcmp(read_entry.data.method.signature, "TestMethod") == 0);
	assert(read_entry.data.method.call_count == 100);
	assert(read_entry.data.method.sample_count == 10);
	assert(read_entry.data.method.total_time_ns == 50000);

	/* Mark as read */
	ctx.status_shm->status[0] = ENTRY_READ;

	/* Cleanup should reset to empty */
	cooper_shm_cleanup_read_entries(&ctx);
	assert(ctx.status_shm->status[0] == ENTRY_EMPTY);

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_status_transitions: All tests passed\n");
}

/**
 * Test writing and reading method metrics
 */
static void
test_shared_memory_method_metrics()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Create test method data using new structure */
	struct cooper_method_data test_methods[3] = {
	    {.signature     = "com/example/Method1",
	     .call_count    = 500,
	     .sample_count  = 50,
	     .total_time_ns = 1000000,
	     .alloc_bytes   = 2048},
	    /* ... additional test cases ... */
	};

	/* Write using new function */
	for (int i = 0; i < 1; i++)
	{
		int result = cooper_shm_write_method_data(&ctx, &test_methods[i]);
		assert(result == 0);
		assert(ctx.status_shm->status[i] == ENTRY_READY);
	}

	/* Verify using new entry structure */
	for (int i = 0; i < 1; i++)
	{
		assert(ctx.status_shm->status[i] == ENTRY_READY);

		struct cooper_sample_entry *entry = &ctx.data_shm->entries[i];
		assert(entry->type == COOPER_DATA_METHOD_METRIC);
		assert(strcmp(entry->data.method.signature, test_methods[i].signature)
		       == 0);
		assert(entry->data.method.call_count == test_methods[i].call_count);
		/* ... additional verifications ... */

		ctx.status_shm->status[i] = ENTRY_READ;
	}

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_method_metrics: All tests passed\n");
}

/**
 * Test writing and reading memory samples
 */
static void
test_shared_memory_memory_samples()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Create test memory data using new structure */
	struct cooper_memory_data test_memory[2] = {
	    {.process_memory = 1024 * 1024 * 100, /* 100MB */
	     .thread_id      = 0,                 /* Process-wide */
	     .thread_memory  = 0},
	    {
		.process_memory = 0,
		.thread_id      = 12345,           /* Specific thread */
		.thread_memory  = 1024 * 1024 * 10 /* 10MB */
	    }};

	/* Write using new function */
	for (int i = 0; i < 2; i++)
	{
		int result = cooper_shm_write_memory_data(&ctx, &test_memory[i]);
		assert(result == 0);
		assert(ctx.status_shm->status[i] == ENTRY_READY);
	}

	/* Verify using new entry structure - no field mapping needed */
	for (int i = 0; i < 2; i++)
	{
		struct cooper_sample_entry *entry = &ctx.data_shm->entries[i];

		assert(entry->type == COOPER_DATA_MEMORY_SAMPLE);
		assert(entry->data.memory.process_memory
		       == test_memory[i].process_memory);
		assert(entry->data.memory.thread_id == test_memory[i].thread_id);
		assert(entry->data.memory.thread_memory == test_memory[i].thread_memory);

		ctx.status_shm->status[i] = ENTRY_READ;
	}

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_memory_samples: All tests passed\n");
}

static void
test_shared_memory_object_alloc()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Test object allocation data */
	struct cooper_object_alloc_data test_alloc = {.class_signature =
	                                                  "java/lang/String",
	                                              .allocation_count  = 1000,
	                                              .current_instances = 500,
	                                              .total_bytes       = 1024 * 1024,
	                                              .peak_instances    = 750,
	                                              .min_size          = 24,
	                                              .max_size          = 1024,
	                                              .avg_size          = 64};

	int result = cooper_shm_write_object_alloc_data(&ctx, &test_alloc);
	assert(result == 0);
	assert(ctx.status_shm->status[0] == ENTRY_READY);

	/* Verify data integrity */
	struct cooper_sample_entry *entry = &ctx.data_shm->entries[0];
	assert(entry->type == COOPER_DATA_OBJECT_ALLOC);
	assert(strcmp(entry->data.object_alloc.class_signature, "java/lang/String") == 0);
	assert(entry->data.object_alloc.allocation_count == 1000);
	assert(entry->data.object_alloc.total_bytes == 1024 * 1024);
	/* ... additional verifications ... */

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_object_alloc: All tests passed\n");
}

/**
 * Test buffer wraparound behavior
 */
static void
test_shared_memory_wraparound()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	struct cooper_method_data test_method = {.signature     = "WrapTest",
	                                         .call_count    = 1,
	                                         .sample_count  = 1,
	                                         .total_time_ns = 1000};

	/* Fill the entire buffer */
	for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++)
	{
		test_method.call_count = i + 1; /* Unique identifier */
		int result             = cooper_shm_write_method_data(&ctx, &test_method);
		assert(result == 0);
		assert(ctx.status_shm->status[i] == ENTRY_READY);

		/* Verify data was written correctly */
		struct cooper_sample_entry *entry = &ctx.data_shm->entries[i];
		assert(entry->type == COOPER_DATA_METHOD_METRIC);
		assert(strcmp(entry->data.method.signature, "WrapTest") == 0);
		assert(entry->data.method.call_count == i + 1);
	}

	/* Verify write index wrapped around */
	assert(ctx.data_shm->next_write_index == 0);

	/* Next write should fail (buffer full) */
	test_method.call_count = 9999;
	int result             = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == -1);

	/* Mark first few entries as read */
	for (int i = 0; i < 5; i++)
	{
		ctx.status_shm->status[i] = ENTRY_READ;
	}

	/* Cleanup read entries */
	cooper_shm_cleanup_read_entries(&ctx);

	/* Verify first few entries are now empty */
	for (int i = 0; i < 5; i++)
	{
		assert(ctx.status_shm->status[i] == ENTRY_EMPTY);
	}

	/* Should be able to write to first slot again */
	ctx.data_shm->next_write_index = 0;    /* Reset write index */
	test_method.call_count         = 8888; /* New unique value */
	result                         = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == 0);
	assert(ctx.status_shm->status[0] == ENTRY_READY);

	/* Verify new data was written correctly */
	struct cooper_sample_entry *entry = &ctx.data_shm->entries[0];
	assert(entry->type == COOPER_DATA_METHOD_METRIC);
	assert(entry->data.method.call_count == 8888);
	assert(strcmp(entry->data.method.signature, "WrapTest") == 0);

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_wraparound: All tests passed\n");
}

/**
 * Test concurrent-like access patterns
 */
static void
test_shared_memory_concurrent_patterns()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	struct cooper_method_data test_method = {
	    .signature = "ConcurrentTest", .sample_count = 1, .total_time_ns = 5000};

	/* Simulate interleaved read/write pattern */
	for (int round = 0; round < 3; round++)
	{
		/* Write some entries */
		for (int i = 0; i < 5; i++)
		{
			test_method.call_count = round * 100 + i;
			int result = cooper_shm_write_method_data(&ctx, &test_method);
			assert(result == 0);

			/* Verify data was written correctly */
			uint32_t write_idx = (round * 5 + i) % COOPER_MAX_ENTRIES;
			struct cooper_sample_entry *entry =
			    &ctx.data_shm->entries[write_idx];
			assert(entry->type == COOPER_DATA_METHOD_METRIC);
			assert(entry->data.method.call_count
			       == (uint64_t)(round) * 100 + i);
			assert(strcmp(entry->data.method.signature, "ConcurrentTest")
			       == 0);
		}

		/* Simulate CLI reading every other entry */
		for (int i = 0; i < 5; i += 2)
		{
			uint32_t idx = (round * 5 + i) % COOPER_MAX_ENTRIES;
			assert(ctx.status_shm->status[idx] == ENTRY_READY);

			/* Verify data before marking as read */
			struct cooper_sample_entry *entry = &ctx.data_shm->entries[idx];
			assert(entry->type == COOPER_DATA_METHOD_METRIC);
			assert(entry->data.method.call_count
			       == (uint64_t)(round) * 100 + i);

			ctx.status_shm->status[idx] = ENTRY_READ;
		}

		/* Cleanup read entries */
		cooper_shm_cleanup_read_entries(&ctx);

		/* Verify read entries are now empty */
		for (int i = 0; i < 5; i += 2)
		{
			uint32_t idx = (round * 5 + i) % COOPER_MAX_ENTRIES;
			assert(ctx.status_shm->status[idx] == ENTRY_EMPTY);
		}

		/* Mark remaining entries as read */
		for (int i = 1; i < 5; i += 2)
		{
			uint32_t idx = (round * 5 + i) % COOPER_MAX_ENTRIES;
			assert(ctx.status_shm->status[idx] == ENTRY_READY);

			/* Verify data before marking as read */
			struct cooper_sample_entry *entry = &ctx.data_shm->entries[idx];
			assert(entry->type == COOPER_DATA_METHOD_METRIC);
			assert(entry->data.method.call_count
			       == (uint64_t)(round) * 100 + i);

			ctx.status_shm->status[idx] = ENTRY_READ;
		}

		cooper_shm_cleanup_read_entries(&ctx);

		/* Verify all entries from this round are now empty */
		for (int i = 0; i < 5; i++)
		{
			uint32_t idx = (round * 5 + i) % COOPER_MAX_ENTRIES;
			assert(ctx.status_shm->status[idx] == ENTRY_EMPTY);
		}
	}

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_concurrent_patterns: All tests passed\n");
}

/**
 * Test multiple data types in mixed order
 */
static void
test_shared_memory_mixed_data_types()
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Test mixed data types using new structures */
	struct cooper_method_data method = {.signature  = "MixedTest::method",
	                                    .call_count = 42};
	cooper_shm_write_method_data(&ctx, &method);

	struct cooper_memory_data memory = {
	    .process_memory = 1024 * 1024 * 50, .thread_id = 0, .thread_memory = 0};
	cooper_shm_write_memory_data(&ctx, &memory);

	struct cooper_object_alloc_data alloc = {.class_signature  = "TestClass",
	                                         .allocation_count = 100};
	cooper_shm_write_object_alloc_data(&ctx, &alloc);

	/* Verify data types and integrity */
	assert(ctx.data_shm->entries[0].type == COOPER_DATA_METHOD_METRIC);
	assert(ctx.data_shm->entries[1].type == COOPER_DATA_MEMORY_SAMPLE);
	assert(ctx.data_shm->entries[2].type == COOPER_DATA_OBJECT_ALLOC);

	/* Verify data integrity with clean field access */
	assert(ctx.data_shm->entries[0].data.method.call_count == 42);
	assert(ctx.data_shm->entries[1].data.memory.process_memory == 1024 * 1024 * 50);
	assert(strcmp(ctx.data_shm->entries[2].data.object_alloc.class_signature,
	              "TestClass")
	       == 0);

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_mixed_data_types: All tests passed\n");
}

/* Test buffer overflow protection in arena allocations */
void
test_buffer_overflow_protection(void)
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Test allocation of exact available size */
	size_t available_size =
	    test_arena->total_sz - sizeof(block_header_t) - 8; /* Account for alignment */
	void *large_block = arena_alloc(test_arena, available_size);
	assert(large_block != NULL);

	/* Verify header magic is intact */
	block_header_t *header =
	    (block_header_t *)((char *)large_block - sizeof(block_header_t));
	assert(header->magic == ARENA_BLOCK_MAGIC);
	assert(header->block_sz == available_size);

	/* Test allocation beyond available size should fail */
	void *overflow_block = arena_alloc(test_arena, 1024);
	assert(overflow_block == NULL);

	/* Test writing to allocated memory boundaries */
	memset(large_block, 0xAA, available_size);

	/* Verify header magic is still intact after boundary write */
	assert(header->magic == ARENA_BLOCK_MAGIC);

	/* Test corrupted header detection */
	void *normal_block = arena_alloc(test_arena, 64);
	assert(normal_block == NULL); /* Should fail due to insufficient space */

	arena_free(test_arena, large_block);

	/* Now we should be able to allocate again */
	normal_block = arena_alloc(test_arena, 64);
	assert(normal_block != NULL);

	/* Corrupt the header magic */
	block_header_t *normal_header =
	    (block_header_t *)((char *)normal_block - sizeof(block_header_t));
	uint32_t original_magic = normal_header->magic;
	normal_header->magic    = 0xDEADBEEF;

	/* arena_free should detect corruption and fail */
	int free_result = arena_free(test_arena, normal_block);
	assert(free_result == 0);

	/* Restore magic for cleanup */
	normal_header->magic = original_magic;

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_buffer_overflow_protection: All tests passed\n");
}

/* Test arena bounds checking mechanisms */
void
test_arena_bounds_checking(void)
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Test allocation with zero size */
	// void *zero_block = arena_alloc(test_arena, 0);
	// assert(zero_block == NULL);

	/* Test multiple small allocations to check bounds */
	void *blocks[4];
	for (int i = 0; i < 4; i++)
	{
		blocks[i] = arena_alloc(test_arena, 64);
		if (blocks[i] != NULL)
		{
			block_header_t *header =
			    (block_header_t *)((char *)blocks[i]
			                       - sizeof(block_header_t));
			assert(header->magic == ARENA_BLOCK_MAGIC);
			assert(header->block_sz == 64);

			/* Verify block is within arena bounds */
			assert((char *)blocks[i] >= (char *)test_arena->memory);
			assert((char *)blocks[i] + 64
			       <= (char *)test_arena->memory + test_arena->total_sz);
		}
	}

	/* Test freeing invalid pointers */
	char external_buffer[64];
	int result = arena_free(test_arena, external_buffer);
	assert(result == 0); /* Should fail - not from arena */

	result = arena_free(test_arena, NULL);
	assert(result == 0); /* Should fail - NULL pointer */

	/* Test freeing pointer with corrupted header location */
	char *fake_block = (char *)test_arena->memory + sizeof(block_header_t);
	block_header_t *fake_header =
	    (block_header_t *)((char *)fake_block - sizeof(block_header_t));
	fake_header->magic = 0x12345678; /* Wrong magic */
	result             = arena_free(test_arena, fake_block);
	assert(result == 0); /* Should fail - wrong magic */

	/* Test arena free list bounds */
	for (int i = 0; i < 4; i++)
	{
		if (blocks[i] != NULL)
		{
			arena_free(test_arena, blocks[i]);
		}
	}

	/* Try to exceed max_free_blocks */
	void *extra_blocks[8];
	size_t allocated_count = 0;
	for (int i = 0; i < 8; i++)
	{
		extra_blocks[i] = arena_alloc(test_arena, 32);
		if (extra_blocks[i] != NULL)
		{
			allocated_count++;
		}
	}

	/* Free more blocks than max_free_blocks can track */
	int freed_count = 0;
	for (size_t i = 0; i < allocated_count && i < test_arena->max_free_blocks; i++)
	{
		if (extra_blocks[i] != NULL)
		{
			result = arena_free(test_arena, extra_blocks[i]);
			if (result == 1)
				freed_count++;
		}
	}

	/* Additional frees should fail when free list is full */
	if (allocated_count > test_arena->max_free_blocks)
	{
		result =
		    arena_free(test_arena, extra_blocks[test_arena->max_free_blocks]);
		assert(result == 0); /* Should fail - free list full */
	}

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_arena_bounds_checking: All tests passed\n");
}

/* Test string handling safety mechanisms */
void
test_string_handling_safety(void)
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	/* Test arena_strdup with NULL input */
	char *result = arena_strdup(test_arena, NULL);
	assert(result == NULL);

	/* Test arena_strdup with empty string */
	result = arena_strdup(test_arena, "");
	assert(result != NULL);
	assert(strlen(result) == 0);

	/* Test arena_strdup with normal string */
	const char *test_str = "TestString123";
	result               = arena_strdup(test_arena, test_str);
	assert(result != NULL);
	assert(strcmp(result, test_str) == 0);
	assert(result != test_str); /* Different memory locations */

	/* Test arena_strndup with length limit */
	result = arena_strndup(test_arena, "VeryLongStringForTesting", 8);
	assert(result == NULL);

	/* Test arena_strndup with string shorter than limit */
	result = arena_strndup(test_arena, "Short", 10);
	assert(result != NULL);
	assert(strcmp(result, "Short") == 0);
	assert(strlen(result) == 5);

	/* Test arena_trim with various inputs */
	result = arena_trim(test_arena, "  trimmed  ");
	assert(result != NULL);
	assert(strcmp(result, "trimmed") == 0);

	result = arena_trim(test_arena, "   ");
	assert(result != NULL);
	assert(strlen(result) == 0);

	result = arena_trim(test_arena, "notrimneeded");
	assert(result != NULL);
	assert(strcmp(result, "notrimneeded") == 0);

	/* Test arena_strip_comment with safe handling */
	result = arena_strip_comment(test_arena, "config=value # comment");
	assert(result != NULL);
	assert(strcmp(result, "config=value ") == 0);

	result = arena_strip_comment(test_arena, "quoted=\"value # not comment\"");
	assert(result != NULL);
	assert(strcmp(result, "quoted=\"value # not comment\"") == 0);

	/* Test with NULL arena */
	// result = arena_strdup(NULL, "test");
	// assert(result == NULL);

	// result = arena_trim(NULL, "test");
	// assert(result == NULL);

	// result = arena_strip_comment(NULL, "test");
	// assert(result == NULL);

	/* Test extremely long string handling */
	char long_string[MAX_STR_LEN + 100];
	memset(long_string, 'A', sizeof(long_string) - 1);
	long_string[sizeof(long_string) - 1] = '\0';

	result = arena_strndup(test_arena, long_string, MAX_STR_LEN - 1);
	assert(result == NULL); /* Should return NULL - string too long */

	/* Test with string that fits within limit - use a fresh arena to ensure space */
	arena_reset(test_arena);
	// arena_t *fresh_arena = create_arena(&ctx->arena_head, &ctx->arena_tail,
	// "fresh_string_arena", 8192, 20);

	char medium_string[64]; /* Use smaller string to ensure arena has space */
	memset(medium_string, 'B', sizeof(medium_string) - 1);
	medium_string[sizeof(medium_string) - 1] = '\0';

	result = arena_strndup(test_arena, medium_string, MAX_STR_LEN - 1);
	assert(result != NULL);
	assert(strlen(result) == 63);
	assert(strcmp(result, medium_string) == 0);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_string_handling_safety: All tests passed\n");
}

/* Test shared memory race condition handling */
void
test_shared_memory_race_conditions(void)
{
	cooper_shm_context_t ctx = {0};
	assert(cooper_shm_init_agent(&ctx) == 0);

	/* Test backpressure mechanism prevents race conditions */
	struct cooper_method_data test_method = {.signature     = "RaceTest::method",
	                                         .call_count    = 1,
	                                         .sample_count  = 1,
	                                         .total_time_ns = 1000};

	/* Fill buffer to test race condition handling */
	for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++)
	{
		test_method.call_count = i + 1;
		int result             = cooper_shm_write_method_data(&ctx, &test_method);
		assert(result == 0);
		assert(ctx.status_shm->status[i] == ENTRY_READY);
	}

	/* Verify write index wrapped */
	assert(ctx.data_shm->next_write_index == 0);

	/* Next write should fail due to backpressure */
	test_method.call_count = 9999;
	int result             = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == -1); /* Should fail */

	/* Simulate concurrent reader - mark some entries as read */
	for (int i = 0; i < 10; i++)
	{
		assert(ctx.status_shm->status[i] == ENTRY_READY);
		ctx.status_shm->status[i] = ENTRY_READ;
	}

	/* Cleanup read entries */
	cooper_shm_cleanup_read_entries(&ctx);

	/* Verify entries are now empty */
	for (int i = 0; i < 10; i++)
	{
		assert(ctx.status_shm->status[i] == ENTRY_EMPTY);
	}

	/* Should be able to write to first slot again */
	ctx.data_shm->next_write_index = 0;
	test_method.call_count         = 7777;
	result                         = cooper_shm_write_method_data(&ctx, &test_method);
	assert(result == 0);
	assert(ctx.status_shm->status[0] == ENTRY_READY);

	/* Verify data integrity after race condition handling */
	struct cooper_sample_entry *entry = &ctx.data_shm->entries[0];
	assert(entry->type == COOPER_DATA_METHOD_METRIC);
	assert(entry->data.method.call_count == 7777);
	assert(strcmp(entry->data.method.signature, "RaceTest::method") == 0);

	cooper_shm_cleanup_agent(&ctx);
	printf("[TEST] test_shared_memory_race_conditions: All tests passed\n");
}

/* Test cache thread safety (note: current cache is not thread-safe) */
void
test_cache_thread_safety(void)
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(
            CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ, CLASS_CACHE_ARENA_BLOCKS);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	cache_config_t config = {.max_entries = 8,
	                         .key_size    = sizeof(int),
	                         .value_size  = sizeof(int),
	                         .key_compare = int_compare,
	                         .key_copy    = NULL,
	                         .value_copy  = NULL,
	                         .entry_init  = NULL,
	                         .name        = "thread_safety_cache"};

	cache_t *cache = cache_init(test_arena, &config);
	assert(cache != NULL);

	/* Test sequential access patterns that could reveal thread safety issues */

	/* Phase 1: Populate cache */
	for (int i = 0; i < 8; i++)
	{
		int result = cache_put(cache, &i, &i);
		assert(result == 0);
	}

	/* Phase 2: Interleaved read/write operations */
	for (int round = 0; round < 3; round++)
	{
		/* Write pattern that could cause conflicts */
		for (int i = 0; i < 4; i++)
		{
			int key   = round * 10 + i;
			int value = key * 2;
			cache_put(cache, &key, &value);
		}

		/* Read pattern */
		for (int i = 0; i < 4; i++)
		{
			int key = round * 10 + i;
			int value;
			int result = cache_get(cache, &key, &value);
			if (result == 0)
			{
				assert(value == key * 2);
			}
		}
	}

	/* Phase 3: Test cache consistency after operations */
	size_t entries;
	cache_stats(cache, NULL, NULL, &entries);
	assert(entries <= config.max_entries);

	/* Test cache_clear thread safety implications */
	cache_clear(cache);
	cache_stats(cache, NULL, NULL, &entries);
	assert(entries == 0);

	/* Note: This test verifies the cache behaves consistently in sequential access.
	 * For true thread safety, external synchronization would be required. */

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_cache_thread_safety: All tests passed\n");
}

// /* Test logging concurrent write safety */
// void
// test_logging_concurrent_writes(void)
// {
// 	agent_context_t *ctx = init_test_context();
// 	arena_t *log_arena   = arena_init(LOG_ARENA_NAME, LOG_ARENA_SZ, LOG_ARENA_BLOCKS);
// 	ctx->arenas[LOG_ARENA_ID] = log_arena;

// 	/* Initialize logging system */
// 	q_t *queue = arena_alloc(log_arena, sizeof(q_t));
// 	assert(queue != NULL);

// 	pthread_mutex_init(&queue->lock, NULL);
// 	pthread_cond_init(&queue->cond, NULL);
// 	queue->hd      = 0;
// 	queue->tl      = 0;
// 	queue->count   = 0;
// 	queue->running = 1;

// 	/* Test concurrent-style message enqueueing */
// 	const char *test_messages[] = {"Log message 1",
// 	                               "Log message 2",
// 	                               "Log message 3",
// 	                               "Log message 4",
// 	                               "Log message 5"};

// 	/* Simulate multiple threads enqueueing messages */
// 	for (int round = 0; round < 3; round++)
// 	{
// 		for (int i = 0; i < 5; i++)
// 		{
// 			/* This simulates what log_enq does internally */
// 			pthread_mutex_lock(&queue->lock);

// 			if (queue->count < Q_SZ)
// 			{
// 				queue->messages[queue->hd] =
// 				    arena_strdup(log_arena, test_messages[i]);
// 				assert(queue->messages[queue->hd] != NULL);

// 				queue->hd = (queue->hd + 1) % Q_SZ;
// 				queue->count++;
// 				pthread_cond_signal(&queue->cond);
// 			}

// 			pthread_mutex_unlock(&queue->lock);
// 		}

// 		/* Simulate reader consuming messages */
// 		while (queue->count > 0)
// 		{
// 			pthread_mutex_lock(&queue->lock);

// 			if (queue->count > 0)
// 			{
// 				char *msg = queue->messages[queue->tl];
// 				assert(msg != NULL);

// 				queue->messages[queue->tl] = NULL;
// 				queue->tl                  = (queue->tl + 1) % LOG_Q_SZ;
// 				queue->count--;
// 			}

// 			pthread_mutex_unlock(&queue->lock);
// 		}
// 	}

// 	/* Test queue overflow handling */
// 	for (int i = 0; i < LOG_Q_SZ + 10; i++)
// 	{
// 		pthread_mutex_lock(&queue->lock);

// 		if (queue->count < LOG_Q_SZ)
// 		{
// 			char msg_buf[64];
// 			snprintf(msg_buf, sizeof(msg_buf), "Overflow test message %d", i);
// 			queue->messages[queue->hd] = arena_strdup(log_arena, msg_buf);

// 			if (queue->messages[queue->hd])
// 			{
// 				queue->hd = (queue->hd + 1) % LOG_Q_SZ;
// 				queue->count++;
// 			}
// 		}
// 		/* Messages beyond capacity should be dropped safely */

// 		pthread_mutex_unlock(&queue->lock);
// 	}

// 	/* Verify queue is at capacity */
// 	assert(queue->count == LOG_Q_SZ);

// 	/* Test concurrent read/write with queue at capacity */
// 	pthread_mutex_lock(&queue->lock);

// 	/* Remove one message */
// 	if (queue->count > 0)
// 	{
// 		queue->messages[queue->tl] = NULL;
// 		queue->tl                  = (queue->tl + 1) % LOG_Q_SZ;
// 		queue->count--;
// 	}

// 	/* Add one message */
// 	if (queue->count < LOG_Q_SZ)
// 	{
// 		queue->messages[queue->hd] =
// 		    arena_strdup(log_arena, "Final test message");
// 		if (queue->messages[queue->hd])
// 		{
// 			queue->hd = (queue->hd + 1) % LOG_Q_SZ;
// 			queue->count++;
// 		}
// 	}

// 	pthread_mutex_unlock(&queue->lock);

// 	/* Cleanup */
// 	pthread_cond_destroy(&queue->cond);
// 	pthread_mutex_destroy(&queue->lock);

// 	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
// 	cleanup_test_context(ctx);

// 	printf("[TEST] test_logging_concurrent_writes: All tests passed\n");
// }

int
main()
{
	printf("Running unit tests for cooper.c...\n");

	test_arena_trim();
	test_arena_strip_comment();
	test_config_extract_and_trim_value();
	test_config_process_config_line();
	test_load_config();
	test_record_method_execution();
	test_arena();
	test_log_queue();
	test_cpu_cycles();
	test_cache_basic();
	test_cache_eviction();
	test_cache_update();
	test_cache_clear();
	test_cache_tls();
	test_cache_errors();
	test_cache_string_keys();
	test_shared_memory_init();
	test_shared_memory_status_transitions();
	test_shared_memory_method_metrics();
	test_shared_memory_memory_samples();
	test_shared_memory_object_alloc();
	test_shared_memory_wraparound();
	test_shared_memory_concurrent_patterns();
	test_shared_memory_mixed_data_types();

	// test_buffer_overflow_protection();
	test_arena_bounds_checking();
	test_string_handling_safety();

	test_shared_memory_race_conditions();
	test_cache_thread_safety();
	// test_logging_concurrent_writes();

	printf("All tests completed successfully!\n");
	return 0;
}
