/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"
#include "arena_str.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Metric flag constants - these should match cooper.h */
#define METRIC_FLAG_TIME    0x0001
#define METRIC_FLAG_MEMORY  0x0002
#define METRIC_FLAG_CPU     0x0004

/**
 * Parse metrics string and return flags
 */
static unsigned int parse_metric_flags(const char *metrics_str)
{
    unsigned int flags = 0;
    
    if (!metrics_str)
        return METRIC_FLAG_TIME; /* Default to time only */
    
    if (strstr(metrics_str, "time")) flags |= METRIC_FLAG_TIME;
    if (strstr(metrics_str, "memory")) flags |= METRIC_FLAG_MEMORY;
    if (strstr(metrics_str, "cpu")) flags |= METRIC_FLAG_CPU;
    
    /* If no valid metrics specified, default to time */
    if (flags == 0)
        flags = METRIC_FLAG_TIME;
    
    return flags;
}

/**
 * Add a method filter to the configuration
 */
static int config_add_filter(arena_t *arena, cooper_config_t *config,
                            const char *class_sig, const char *method_name, 
                            const char *method_sig, int sample_rate, 
                            unsigned int metric_flags)
{
    assert(arena != NULL);
    assert(config != NULL);
    
    /* Check if we have space */
    if (config->num_filters >= config->filters_capacity) {
        LOG_ERROR("Maximum number of method filters reached (%zu)\n", config->filters_capacity);
        return 1;
    }
    
    method_filter_entry_t *filter = &config->filters[config->num_filters];
    
    /* Allocate and copy strings */
    filter->class_signature = arena_strdup(arena, class_sig);
    filter->method_name = arena_strdup(arena, method_name);
    filter->method_signature = arena_strdup(arena, method_sig);
    
    if (!filter->class_signature || !filter->method_name || !filter->method_signature) {
        LOG_ERROR("Failed to allocate memory for method filter\n");
        return 1;
    }
    
    filter->sample_rate = sample_rate;
    filter->metric_flags = metric_flags;
    
    config->num_filters++;
    
    LOG_DEBUG("Added filter: %s:%s:%s (rate=%d, flags=%u)\n", 
        class_sig, method_name, method_sig, sample_rate, metric_flags);
    
    return 0;
}

int config_init(arena_t *arena, cooper_config_t *config)
{
    assert(arena != NULL);
    assert(config != NULL);
    
    if (!arena || !config) return 1;
    
    /* Initialize with defaults */
    memset(config, 0, sizeof(cooper_config_t));
    
    config->default_sample_rate = 100;
    config->export_interval = 60;
    config->mem_sample_interval = 1;
    config->filters_capacity = MAX_FILTER_ENTRIES;
    
    /* Allocate filters array */
    config->filters = arena_alloc(arena, MAX_FILTER_ENTRIES * sizeof(method_filter_entry_t));
    if (!config->filters) {
        LOG_ERROR("Failed to allocate memory for filters array\n");
        return 1;
    }
    
    memset(config->filters, 0, MAX_FILTER_ENTRIES * sizeof(method_filter_entry_t));
    
    /* Set default export method */
    config->export_method = arena_strdup(arena, "file");
    if (!config->export_method) {
        LOG_ERROR("Failed to allocate memory for default export method\n");
        return 1;
    }
    
    return 0;
}

int config_parse(arena_t *arena, const char *config_file, cooper_config_t *config)
{
    assert(arena != NULL);
    assert(config != NULL);
    
    if (!arena || !config) return 1;
    
    /* Initialize config with defaults first */
    if (config_init(arena, config) != 0) {
        return 1;
    }
    
    /* Use default config file if none specified */
    if (!config_file) {
        config_file = DEFAULT_CFG_FILE;
    }
    
    LOG_INFO("Loading config from: %s\n", config_file);
    
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        LOG_ERROR("Could not open config file: %s\n", config_file);
        return 1;
    }
    
    char line[256];
    char *current_section = NULL;
    
    while (fgets(line, sizeof(line), fp)) {
        /* Process the line (strip comments, trim whitespace) */
        char *processed = arena_process_config_line(arena, line);

        if (!processed || processed[0] == '\0')
            continue;  /* Skip empty lines */
        
        /* Handle section headers */
        if (processed[0] == '[') 
        {
            current_section = processed;
            continue;
        }
        
        /* Skip any data before the first section */
        if (!current_section)
            continue;
        
        /* Parse based on current section */
        if (strcmp(current_section, "[sample_rate]") == 0) {
            char *value = arena_extract_and_trim_value(arena, processed);
            if (value && strstr(processed, "rate")) {
                int rate;
                if (sscanf(value, "%d", &rate) == 1 && rate > 0) {
                    config->default_sample_rate = rate;
                    LOG_DEBUG("Set default sample rate: %d\n", rate);
                }
            }
        }
        else if (strcmp(current_section, "[method_signatures]") == 0) {
            /* Skip filter array markers */
            if (strncmp(processed, "filters =", 9) == 0 || processed[0] == ']')
                continue;
            
            /* Parse filter entry: class_signature:method_name:method_signature:sample_rate:metrics */
            char class_sig[256], method_name[256], method_sig[256];
            int sample_rate;
            char metrics[256] = {0};
            
            /* Initialize with defaults */
            strcpy(method_name, "*");
            strcpy(method_sig, "*");
            sample_rate = config->default_sample_rate;
            
            /* Try to parse the filter entry */
            int parsed = sscanf(processed, "%255[^:]:%255[^:]:%255[^:]:%d:%255s", 
                              class_sig, method_name, method_sig, &sample_rate, metrics);
            
            if (parsed < 1) 
            {
                LOG_ERROR("Invalid method filter format: %s\n", processed);
                continue;
            }
            
            /* Parse metric flags */
            unsigned int metric_flags = parse_metric_flags(metrics);
            
            /* Add the filter */
            if (config_add_filter(arena, config, class_sig, method_name, 
                                method_sig, sample_rate, metric_flags) != 0) {
                LOG_ERROR("Failed to add method filter: %s\n", processed);
                continue;
            }
        }
        else if (strcmp(current_section, "[sample_file_location]") == 0) {
            char *value = arena_extract_and_trim_value(arena, processed);
            if (value && strstr(processed, "path")) {
                config->sample_file_path = value;
                LOG_DEBUG("Set sample file path: %s\n", value);
            }
        }
        else if (strcmp(current_section, "[export]") == 0) {
            char *value = arena_extract_and_trim_value(arena, processed);
            if (!value) continue;
            
            if (strstr(processed, "method")) {
                config->export_method = value;
                LOG_DEBUG("Set export method: %s\n", value);
            }
            else if (strstr(processed, "interval")) {
                int interval;
                if (sscanf(value, "%d", &interval) == 1 && interval > 0) {
                    config->export_interval = interval;
                    LOG_DEBUG("Set export interval: %d\n", interval);
                }
            }
        }
    }
    
    fclose(fp);
    
    LOG_INFO("Config loaded: default_rate=%d, filters=%zu, path=%s, method=%s, export_interval=%d\n",
        config->default_sample_rate, config->num_filters,
        config->sample_file_path ? config->sample_file_path : "NULL",
        config->export_method ? config->export_method : "NULL",
        config->export_interval);
    
    return 0;
}