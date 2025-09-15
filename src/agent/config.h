/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../lib/arena.h"
#include "../lib/arena_str.h"
#include "../lib/log.h"
#include "cooper_types.h"

#define DEFAULT_CFG_FILE    "trace.ini"
#define MAX_FILTER_ENTRIES  256
#define MAX_PACKAGE_FILTERS 32

typedef struct pattern_filter_entry pattern_filter_entry_t;
typedef struct pattern_filter pattern_filter_t;
typedef struct cooper_config cooper_config_t;

struct pattern_filter_entry
{
	char *class_pattern;     /**< e.g. "Lcom/github/foamdino/\*" */
	char *method_pattern;    /**< e.g. "handle*" or "*" "*/
	char *signature_pattern; /**< e.g. "*" or "()V" */
	int sample_rate;
	unsigned int metric_flags;
};

struct pattern_filter
{
	pattern_filter_entry_t *entries;
	size_t num_entries;
	size_t capacity;
};

/**
 * Complete configuration for the Cooper agent
 */
struct cooper_config
{
	/* Global settings */
	int default_sample_rate; /**< Default sample rate */
	char *sample_file_path;  /**< Path to output file */
	char *export_method;     /**< Export method (currently only "file") */
	int export_interval;     /**< Export interval in seconds */
	int mem_sample_interval; /**< Memory sampling interval in seconds */

	pattern_filter_t unified_filter;
};

/**
 * Parse configuration from file
 *
 * @param arena         Arena to use for string allocations
 * @param config_file   Path to config file, or NULL for default
 * @param config        Output configuration structure
 * @return              0 on success, 1 on failure
 */
int config_parse(arena_t *arena, const char *config_file, cooper_config_t *config);

/**
 * Initialize configuration structure with defaults
 *
 * @param arena         Arena to use for allocations
 * @param config        Configuration structure to initialize
 * @return              0 on success, 1 on failure
 */
int config_init(arena_t *arena, cooper_config_t *config);

/**
 * Extract value part from a "key = value" string and trim it, using arena allocation
 * Also handles quoted values by removing surrounding quotes
 *
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Extracted and trimmed value, or NULL if no value found or on error
 */
char *config_extract_and_trim_value(arena_t *arena, const char *line);

/**
 * Process a line from a configuration file - strip comments and trim whitespace
 *
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Processed line, or NULL on error
 */
char *config_process_config_line(arena_t *arena, const char *line);

int config_pattern_match(const char *pattern, const char *text);

#endif /* CONFIG_H */