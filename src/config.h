/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "arena.h"

#define DEFAULT_CFG_FILE "trace.ini"
#define MAX_FILTER_ENTRIES 256

typedef struct method_filter_entry method_filter_entry_t;
typedef struct cooper_config cooper_config_t;

/**
 * Represents a single method filter from the configuration
 */
struct method_filter_entry {
    char *class_signature;      /**< Class signature pattern */
    char *method_name;          /**< Method name pattern */
    char *method_signature;     /**< Method signature pattern */
    int sample_rate;            /**< Sample rate for this method */
    unsigned int metric_flags;  /**< Bitfield of metrics to collect */
};

/**
 * Complete configuration for the Cooper agent
 */
struct cooper_config {
    /* Global settings */
    int default_sample_rate;    /**< Default sample rate */
    char *sample_file_path;     /**< Path to output file */
    char *export_method;        /**< Export method (currently only "file") */
    int export_interval;        /**< Export interval in seconds */
    int mem_sample_interval;    /**< Memory sampling interval in seconds */
    
    /* Method filters */
    method_filter_entry_t *filters;  /**< Array of method filters */
    size_t num_filters;              /**< Number of filters */
    size_t filters_capacity;         /**< Capacity of filters array */
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

#endif /* CONFIG_H */