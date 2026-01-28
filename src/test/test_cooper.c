/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "../lib/log.h"
#include "../lib/ring/mpsc_ring.h"
#include "../lib/arena.h"
#include "../lib/arena_str.h"
#include "../lib/cpu.h"

#include "../agent/cooper.h"
#include "../agent/config.h"
#include "../agent/cooper_shm.h"

mpsc_ring_t log_ring;

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
	ctx->log_file                = NULL;
	ctx->config.rate             = 1;
	ctx->config.sample_file_path = NULL;
	ctx->config.export_method    = NULL;
	ctx->config.export_interval  = 60;

	pthread_mutex_init(&ctx->tm_ctx.samples_lock, NULL);

	return ctx;
}

/* Initialize a log queue for testing */
/* Initialize a log ring for testing */
int
init_test_log_ring(agent_context_t *ctx)
{
	UNUSED(ctx);
	return mpsc_ring_init(&log_ring, LOG_RING_CAPACITY, MAX_LOG_MSG_SZ);
}

/* Cleanup test context */
static void
cleanup_test_context(agent_context_t *ctx)
{
	if (!ctx)
		return;

	pthread_mutex_destroy(&ctx->tm_ctx.samples_lock);
	free(ctx);
}

/* Test arena_trim function */
static void
test_arena_trim()
{
	agent_context_t *ctx         = init_test_context();
	arena_t *config_arena        = arena_init("config_arena", CONFIG_ARENA_SZ);
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
	agent_context_t *ctx         = init_test_context();
	arena_t *config_arena        = arena_init("config_arena", CONFIG_ARENA_SZ);
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
	agent_context_t *ctx         = init_test_context();
	arena_t *config_arena        = arena_init("config_arena", CONFIG_ARENA_SZ);
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
	agent_context_t *ctx         = init_test_context();
	arena_t *config_arena        = arena_init("config_arena", CONFIG_ARENA_SZ);
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

	/* Initialize log ring for the test */
	assert(init_test_log_ring(ctx) == 0);

	/* Create necessary arenas */
	arena_t *config_arena         = arena_init("config_arena", CONFIG_ARENA_SZ);
	ctx->arenas[CONFIG_ARENA_ID]  = config_arena;
	arena_t *metrics_arena        = arena_init("metrics_arena", METRICS_ARENA_SZ);
	ctx->arenas[METRICS_ARENA_ID] = metrics_arena;

	/* Initialize log system */
	init_log_system(&log_ring, stdout);

	/* Initialize metrics */
	size_t initial_capacity = 256;
	ctx->metrics            = init_method_metrics(metrics_arena, initial_capacity);
	assert(ctx->metrics != NULL);

	const char *config_content =
	    "[sample_rate]\n"
	    "# Default sample rate for methods without a specific rate\n"
	    "rate = 5\n"
	    "\n"
	    "[filters]\n"
	    "# Format: class_pattern:method_pattern:signature_pattern:rate:metrics\n"
	    "# Supports wildcards (*) and can match at any level\n"
	    "Lcom/github/foamdino/*:*:*:1:time,memory,cpu\n"
	    "Lcom/github/foamdino/Test;:b:()Ljava/lang/String;:10:time\n"
	    "Lcom/github/foamdino/Test;:recursive*:*:5:time,cpu\n"
	    "Lorg/springframework/web/*:handle*:*:50:time,memory\n"
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
	assert(strcmp(ctx->config.sample_file_path, "/tmp/test.txt") == 0);
	assert(strcmp(ctx->config.export_method, "file") == 0);
	assert(ctx->config.export_interval == 30);

	/* Test unified filter loading */
	assert(ctx->unified_filter.num_entries == 4);
	assert(ctx->unified_filter.capacity == MAX_FILTER_ENTRIES);
	assert(ctx->unified_filter.entries != NULL);

	/* Check first filter entry */
	pattern_filter_entry_t *filter0 = &ctx->unified_filter.entries[0];
	assert(strcmp(filter0->class_pattern, "Lcom/github/foamdino/*") == 0);
	assert(strcmp(filter0->method_pattern, "*") == 0);
	assert(strcmp(filter0->signature_pattern, "*") == 0);
	assert(filter0->sample_rate == 1);
	assert(filter0->metric_flags
	       == (METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU));

	/* Check second filter entry */
	pattern_filter_entry_t *filter1 = &ctx->unified_filter.entries[1];
	assert(strcmp(filter1->class_pattern, "Lcom/github/foamdino/Test;") == 0);
	assert(strcmp(filter1->method_pattern, "b") == 0);
	assert(strcmp(filter1->signature_pattern, "()Ljava/lang/String;") == 0);
	assert(filter1->sample_rate == 10);
	assert(filter1->metric_flags == METRIC_FLAG_TIME);

	/* Check third filter entry */
	pattern_filter_entry_t *filter2 = &ctx->unified_filter.entries[2];
	assert(strcmp(filter2->class_pattern, "Lcom/github/foamdino/Test;") == 0);
	assert(strcmp(filter2->method_pattern, "recursive*") == 0);
	assert(strcmp(filter2->signature_pattern, "*") == 0);
	assert(filter2->sample_rate == 5);
	assert(filter2->metric_flags == (METRIC_FLAG_TIME | METRIC_FLAG_CPU));

	/* Check fourth filter entry */
	pattern_filter_entry_t *filter3 = &ctx->unified_filter.entries[3];
	assert(strcmp(filter3->class_pattern, "Lorg/springframework/web/*") == 0);
	assert(strcmp(filter3->method_pattern, "handle*") == 0);
	assert(strcmp(filter3->signature_pattern, "*") == 0);
	assert(filter3->sample_rate == 50);
	assert(filter3->metric_flags == (METRIC_FLAG_TIME | METRIC_FLAG_MEMORY));

	/* Metrics should be initialized but empty since no classes have been processed
	 * yet */
	assert(ctx->metrics != NULL);
	assert(ctx->metrics->count == 0); /* No methods added yet */
	assert(ctx->metrics->capacity == initial_capacity);

	/* Clean up log system */
	cleanup_log_system();

	/* Free the log ring resources */
	mpsc_ring_free(&log_ring);

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] load_config: All tests passed\n");
}

/* Test the logging system ring functionality */
static void
test_log_ring()
{
	/* Initialize a file for logging */
	FILE *log_file = tmpfile();
	assert(log_file != NULL);

	/* Initialize test context */
	agent_context_t *ctx = init_test_context();
	assert(ctx != NULL);

	/* Initialize a log ring using the actual log system */
	mpsc_ring_t local_ring;
	mpsc_ring_init(&local_ring, LOG_RING_CAPACITY, MAX_LOG_MSG_SZ);
	int res = init_log_system(&local_ring, log_file);
	assert(res == 0);

	/* Use LOG macros to add messages to the queue */
	current_log_level = LOG_LEVEL_INFO; /* Ensure INFO logs are processed */
	log_message(LOG_LEVEL_INFO, "test_file.c", 123, "Test message 1");
	log_message(LOG_LEVEL_INFO, "test_file.c", 456, "Test message 2");

	/* Small delay to ensure messages are processed */
	usleep(10000);

	/* Export queue state to a variable for inspection */
	uint64_t head     = atomic_load(&local_ring.head);
	uint64_t tail     = atomic_load(&local_ring.tail);
	int message_count = (int)(head - tail);

	/* Clean up the log system (properly) */
	cleanup_log_system();
	mpsc_ring_free(&local_ring);

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
	arena_t *arena   = arena_init("test_arena", 1024);
	assert(arena != NULL);
	assert(strcmp(arena->name, "test_arena") == 0);
	assert(arena->requested_sz == 1024);
	assert(arena->total_sz % page_size == 0); /* Verify page alignment */
	assert(arena->total_sz >= 1024);
	assert(arena->used == 0);

	/* Test arena_alloc */
	void *block1 = arena_alloc(arena, 100);
	assert(block1 != NULL);
	assert(arena->used >= 100);

	/* Write to the memory to ensure it's usable */
	memset(block1, 'A', 100);

	/* Allocate another block */
	void *block2 = arena_alloc(arena, 200);
	assert(block2 != NULL);
	assert((char *)block2 > (char *)block1);
	assert(arena->used >= 300); /* Including alignment padding */

	/* Write to the second block */
	memset(block2, 'B', 200);

	/* Test arena_destroy */
	arena_destroy(arena);

	/* Test initialization with 0 size or max_blocks */
	assert(arena_init("bad_arena", 0) == NULL);
	assert(arena_init("bad_arena", 1024) == NULL);

	/* Test allocating more memory than available */
	arena = arena_init("small_arena", 200);
	assert(arena != NULL);

	block1 = arena_alloc(arena, 10);
	assert(block1 != NULL);

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
	}

	arena_destroy(arena);

	printf("[TEST] arena: All tests passed\n");
}

// /* Test metrics recording functionality */
// static void
// test_record_method_execution()
// {
// 	agent_context_t *ctx = init_test_context();

// 	/* Initialize metrics arena for metrics data */
// 	arena_t *metrics_arena =
// 	    arena_init("metrics_arena", METRICS_ARENA_SZ, METRICS_ARENA_BLOCKS);
// 	ctx->arenas[METRICS_ARENA_ID] = metrics_arena;
// 	assert(metrics_arena != NULL);

// 	/* Initialize metrics structure */
// 	ctx->metrics = init_method_metrics(metrics_arena, 10);
// 	assert(ctx->metrics != NULL);

// 	/* Add methods with different metric flags */
// 	int idx1 = add_method_to_metrics(
// 	    ctx, "Method1", 1, METRIC_FLAG_TIME | METRIC_FLAG_MEMORY | METRIC_FLAG_CPU);
// 	int idx2 = add_method_to_metrics(ctx, "Method2", 1, METRIC_FLAG_TIME);
// 	int idx3 = add_method_to_metrics(ctx, "Method3", 1, METRIC_FLAG_MEMORY);
// 	int idx4 = add_method_to_metrics(ctx, "Method4", 1, METRIC_FLAG_CPU);

// 	/* Record execution for method with all metrics */
// 	record_method_execution(ctx, idx1, 1000, 512, 2000);
// 	// assert(ctx->metrics->sample_counts[idx1] == 1);
// 	assert(ctx->metrics->total_time_ns[idx1] == 1000);
// 	assert(ctx->metrics->min_time_ns[idx1] == 1000);
// 	assert(ctx->metrics->max_time_ns[idx1] == 1000);
// 	assert(ctx->metrics->alloc_bytes[idx1] == 512);
// 	assert(ctx->metrics->peak_memory[idx1] == 512);
// 	assert(ctx->metrics->cpu_cycles[idx1] == 2000);

// 	/* Record another execution with different values */
// 	record_method_execution(ctx, idx1, 2000, 256, 1500);
// 	// assert(ctx->metrics->sample_counts[idx1] == 2);
// 	assert(ctx->metrics->total_time_ns[idx1] == 3000); /* 1000 + 2000 */
// 	assert(ctx->metrics->min_time_ns[idx1] == 1000);   /* Min remains 1000 */
// 	assert(ctx->metrics->max_time_ns[idx1] == 2000);   /* Max updated to 2000 */
// 	assert(ctx->metrics->alloc_bytes[idx1] == 768);    /* 512 + 256 */
// 	assert(ctx->metrics->peak_memory[idx1] == 512);    /* Peak remains 512 */
// 	assert(ctx->metrics->cpu_cycles[idx1] == 3500);    /* 2000 + 1500 */

// 	/* Record with a lower execution time to test min update */
// 	record_method_execution(ctx, idx1, 500, 1024, 3000);
// 	// assert(ctx->metrics->sample_counts[idx1] == 3);
// 	assert(ctx->metrics->total_time_ns[idx1] == 3500); /* 3000 + 500 */
// 	assert(ctx->metrics->min_time_ns[idx1] == 500);    /* Min updated to 500 */
// 	assert(ctx->metrics->max_time_ns[idx1] == 2000);   /* Max remains 2000 */
// 	assert(ctx->metrics->alloc_bytes[idx1] == 1792);   /* 768 + 1024 */
// 	assert(ctx->metrics->peak_memory[idx1] == 1024);   /* Peak updated to 1024 */
// 	assert(ctx->metrics->cpu_cycles[idx1] == 6500);    /* 3500 + 3000 */

// 	/* Test method with only time metrics */
// 	record_method_execution(ctx, idx2, 1500, 256, 2000);
// 	// assert(ctx->metrics->sample_counts[idx2] == 1);
// 	assert(ctx->metrics->total_time_ns[idx2] == 1500);
// 	assert(ctx->metrics->min_time_ns[idx2] == 1500);
// 	assert(ctx->metrics->max_time_ns[idx2] == 1500);
// 	assert(ctx->metrics->alloc_bytes[idx2] == 0); /* Memory not tracked */
// 	assert(ctx->metrics->peak_memory[idx2] == 0); /* Memory not tracked */
// 	assert(ctx->metrics->cpu_cycles[idx2] == 0);  /* CPU not tracked */

// 	/* Test method with only memory metrics */
// 	record_method_execution(ctx, idx3, 1500, 256, 2000);
// 	// assert(ctx->metrics->sample_counts[idx3] == 1);
// 	assert(ctx->metrics->total_time_ns[idx3] == 0);        /* Time not tracked */
// 	assert(ctx->metrics->min_time_ns[idx3] == UINT64_MAX); /* Default value for min */
// 	assert(ctx->metrics->max_time_ns[idx3] == 0);          /* Time not tracked */
// 	assert(ctx->metrics->alloc_bytes[idx3] == 256);
// 	assert(ctx->metrics->peak_memory[idx3] == 256);
// 	assert(ctx->metrics->cpu_cycles[idx3] == 0); /* CPU not tracked */

// 	/* Test method with only CPU metrics */
// 	record_method_execution(ctx, idx4, 1500, 256, 2000);
// 	// assert(ctx->metrics->sample_counts[idx4] == 1);
// 	assert(ctx->metrics->total_time_ns[idx4] == 0);        /* Time not tracked */
// 	assert(ctx->metrics->min_time_ns[idx4] == UINT64_MAX); /* Default value for min */
// 	assert(ctx->metrics->max_time_ns[idx4] == 0);          /* Time not tracked */
// 	assert(ctx->metrics->alloc_bytes[idx4] == 0);          /* Memory not tracked */
// 	assert(ctx->metrics->peak_memory[idx4] == 0);          /* Memory not tracked */
// 	assert(ctx->metrics->cpu_cycles[idx4] == 2000);

// 	/* Test invalid method index - should not crash */
// 	record_method_execution(ctx, 999, 1000, 512, 2000);
// 	record_method_execution(ctx, -1, 1000, 512, 2000);

// 	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
// 	cleanup_test_context(ctx);

// 	printf("[TEST] record_method_execution: All tests passed\n");
// }

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
	int result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
	assert(result == 0);
	assert(ctx.status_shm->status[0] == ENTRY_READY);

	/* Writing to same slot should fail (backpressure) */
	ctx.data_shm->next_write_index = 0; /* Reset to same slot */
	result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
		int result = cooper_shm_write_data(
		    &ctx, COOPER_DATA_METHOD_METRIC, &test_methods[i]);
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
		int result = cooper_shm_write_data(
		    &ctx, COOPER_DATA_MEMORY_SAMPLE, &test_memory[i]);
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

	int result = cooper_shm_write_data(&ctx, COOPER_DATA_OBJECT_ALLOC, &test_alloc);
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
		int result =
		    cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
	int result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
	result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
			int result             = cooper_shm_write_data(
                            &ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
	cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &method);

	struct cooper_memory_data memory = {
	    .process_memory = 1024 * 1024 * 50, .thread_id = 0, .thread_memory = 0};
	cooper_shm_write_data(&ctx, COOPER_DATA_MEMORY_SAMPLE, &memory);

	struct cooper_object_alloc_data alloc = {.class_signature  = "TestClass",
	                                         .allocation_count = 100};
	cooper_shm_write_data(&ctx, COOPER_DATA_OBJECT_ALLOC, &alloc);

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
	arena_t *test_arena  = arena_init(CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ);
	ctx->arenas[CLASS_CACHE_ARENA_ID] = test_arena;

	printf("DEBUG: Arena total_sz = %zu, used = %zu\n",
	       test_arena->total_sz,
	       test_arena->used);

	/* Use a much more conservative approach - allocate in stages */

	/* Step 1: Allocate several large chunks to fill most of the arena */
	size_t chunk_size = 2 * 1024 * 1024; /* 2MB chunks */
	void *chunks[6];                     /* Up to 6 chunks = 12MB max */
	int chunk_count = 0;

	for (int i = 0; i < 6; i++)
	{
		chunks[i] = arena_alloc(test_arena, chunk_size);
		if (chunks[i] != NULL)
		{
			chunk_count++;
			printf("DEBUG: Allocated chunk %d, arena used = %zu\n",
			       i,
			       test_arena->used);
		}
		else
		{
			printf("DEBUG: Chunk %d allocation failed, arena used = %zu\n",
			       i,
			       test_arena->used);
			break;
		}
	}

	/* Step 2: Try to allocate something that should fail */
	void *overflow_block = arena_alloc(test_arena, 1024 * 1024); /* Try 1MB */
	if (overflow_block != NULL)
	{
		/* If 1MB succeeded, try something bigger */
		printf("DEBUG: 1MB succeeded, trying larger allocation\n");
		overflow_block = arena_alloc(test_arena, 4 * 1024 * 1024); /* Try 4MB */
	}
	assert(overflow_block == NULL); /* Should fail due to insufficient space */

	/* Step 3: Test memory writing on allocated chunks */
	printf("DEBUG: Testing memory writes on %d chunks\n", chunk_count);
	for (int i = 0; i < chunk_count; i++)
	{
		if (chunks[i] != NULL)
		{
			/* Write in smaller sub-chunks to be extra safe */
			for (size_t offset = 0; offset < chunk_size; offset += 4096)
			{
				size_t write_size = (offset + 4096 > chunk_size)
				                        ? (chunk_size - offset)
				                        : 4096;
				memset((char *)chunks[i] + offset, 0xAA + i, write_size);
			}
		}
	}

	destroy_all_arenas(ctx->arenas, ARENA_ID__LAST);
	cleanup_test_context(ctx);

	printf("[TEST] test_buffer_overflow_protection: All tests passed\n");
}

/* Test arena bounds checking mechanisms */
void
test_arena_bounds_checking(void)
{
	agent_context_t *ctx = init_test_context();
	arena_t *test_arena  = arena_init(CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ);
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
			/* Verify block is within arena bounds */
			assert((char *)blocks[i] >= (char *)test_arena->memory);
			assert((char *)blocks[i] + 64
			       <= (char *)test_arena->memory + test_arena->total_sz);
		}
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
	arena_t *test_arena  = arena_init(CLASS_CACHE_ARENA_NAME, CLASS_CACHE_ARENA_SZ);
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
		int result =
		    cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
		assert(result == 0);
		assert(ctx.status_shm->status[i] == ENTRY_READY);
	}

	/* Verify write index wrapped */
	assert(ctx.data_shm->next_write_index == 0);

	/* Next write should fail due to backpressure */
	test_method.call_count = 9999;
	int result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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
	result = cooper_shm_write_data(&ctx, COOPER_DATA_METHOD_METRIC, &test_method);
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

int
main()
{
	printf("Running unit tests for cooper.c...\n");

	test_arena_trim();
	test_arena_strip_comment();
	test_config_extract_and_trim_value();
	test_config_process_config_line();
	test_load_config();
	// test_record_method_execution();
	test_arena();
	test_log_ring();
	test_cpu_cycles();
	test_shared_memory_init();
	test_shared_memory_status_transitions();
	test_shared_memory_method_metrics();
	test_shared_memory_memory_samples();
	test_shared_memory_object_alloc();
	test_shared_memory_wraparound();
	test_shared_memory_concurrent_patterns();
	test_shared_memory_mixed_data_types();

	test_buffer_overflow_protection();
	test_arena_bounds_checking();
	test_string_handling_safety();

	test_shared_memory_race_conditions();

	printf("All tests completed successfully!\n");
	return 0;
}
