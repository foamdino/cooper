/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

/* Glob-style pattern matching with * wildcard support */
int
config_pattern_match(const char *pattern, const char *text)
{
	assert(pattern != NULL);
	assert(text != NULL);

	const char *p            = pattern;
	const char *t            = text;
	const char *star_pattern = NULL;
	const char *star_text    = NULL;

	while (*t != '\0')
	{
		if (*p == '*')
		{
			/* Record positions for backtracking */
			star_pattern = ++p;
			star_text    = t;
		}
		else if (*p == *t)
		{
			/* Characters match, advance both */
			p++;
			t++;
		}
		else if (star_pattern != NULL)
		{
			/* Mismatch but we have a star, backtrack */
			p = star_pattern;
			t = ++star_text;
		}
		else
		{
			/* No match and no star to backtrack to */
			return 0;
		}
	}

	/* Skip any trailing stars in pattern */
	while (*p == '*')
		p++;

	return *p == '\0'; /* Match if we consumed entire pattern */
}

/**
 * Extract value part from a "key = value" string and trim it, using arena allocation
 * Also handles quoted values by removing surrounding quotes
 *
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Extracted and trimmed value, or NULL if no value found or on error
 */
char *
config_extract_and_trim_value(arena_t *arena, const char *line)
{
	assert(arena != NULL);
	assert(line != NULL);

	if (!arena || !line)
		return NULL;

	/* Find the equals sign */
	const char *eq = strchr(line, '=');
	if (!eq)
		return NULL;

	/* Move to the value part (after the equals sign) */
	const char *value_start = eq + 1;

	// Trim the value part
	char *trimmed_value = arena_trim(arena, value_start);
	if (!trimmed_value)
		return NULL;

	/* Check for quoted value */
	size_t trimmed_len = strlen(trimmed_value);
	if (trimmed_len >= 2 && trimmed_value[0] == '"'
	    && trimmed_value[trimmed_len - 1] == '"')
	{
		/* Allocate space for string without quotes */
		char *unquoted = arena_alloc(
		    arena, trimmed_len - 1); /* -1 because we're removing 2 quotes but
		                                need null terminator */
		if (!unquoted)
			return NULL;

		/* Copy the string without quotes */
		memcpy(unquoted, trimmed_value + 1, trimmed_len - 2);
		unquoted[trimmed_len - 2] = '\0';
		return unquoted;
	}

	return trimmed_value;
}

/**
 * Process a line from a configuration file - strip comments and trim whitespace
 *
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Processed line, or NULL on error
 */
char *
config_process_config_line(arena_t *arena, const char *line)
{
	assert(arena != NULL);
	assert(line != NULL);

	if (!arena || !line)
		return NULL;

	/* First strip comments, then trim whitespace */
	char *without_comments = arena_strip_comment(arena, line);
	if (!without_comments)
		return NULL;

	char *trimmed = arena_trim(arena, without_comments);

	/* We can return trimmed directly - no need to free without_comments
	  as it's managed by the arena */
	return trimmed;
}

/**
 * Parse metrics string and return flags
 */
static unsigned int
config_parse_metric_flags(const char *metrics_str)
{
	unsigned int flags = 0;

	if (!metrics_str)
		return METRIC_FLAG_TIME; /* Default to time only */

	if (strstr(metrics_str, "time"))
		flags |= METRIC_FLAG_TIME;
	if (strstr(metrics_str, "memory"))
		flags |= METRIC_FLAG_MEMORY;
	if (strstr(metrics_str, "cpu"))
		flags |= METRIC_FLAG_CPU;

	/* If no valid metrics specified, default to time */
	if (flags == 0)
		flags = METRIC_FLAG_TIME;

	return flags;
}

int
config_init(arena_t *arena, cooper_config_t *config)
{
	assert(arena != NULL);
	assert(config != NULL);

	if (!arena || !config)
		return 1;

	/* Initialize with defaults */
	memset(config, 0, sizeof(cooper_config_t));

	config->default_sample_rate = 100;
	config->export_interval     = 60;
	config->mem_sample_interval = 1;

	/* Initialize unified filter */
	config->unified_filter.capacity    = MAX_FILTER_ENTRIES;
	config->unified_filter.num_entries = 0;

	/* Allocate unified filter entries array */
	config->unified_filter.entries =
	    arena_alloc(arena, MAX_FILTER_ENTRIES * sizeof(pattern_filter_entry_t));
	if (!config->unified_filter.entries)
	{
		LOG_ERROR("Failed to allocate memory for unified filter entries array\n");
		return 1;
	}

	memset(config->unified_filter.entries,
	       0,
	       MAX_FILTER_ENTRIES * sizeof(pattern_filter_entry_t));

	/* Set default export method */
	config->export_method = arena_strdup(arena, "file");
	if (!config->export_method)
	{
		LOG_ERROR("Failed to allocate memory for default export method\n");
		return 1;
	}

	return 0;
}

int
config_parse(arena_t *arena, const char *config_file, cooper_config_t *config)
{
	assert(arena != NULL);
	assert(config != NULL);

	if (!arena || !config)
		return 1;

	/* Initialize config with defaults first */
	if (config_init(arena, config) != 0)
	{
		return 1;
	}

	/* Use default config file if none specified */
	if (!config_file)
	{
		config_file = DEFAULT_CFG_FILE;
	}

	LOG_INFO("Loading config from: %s\n", config_file);

	FILE *fp = fopen(config_file, "r");
	if (!fp)
	{
		LOG_ERROR("Could not open config file: %s\n", config_file);
		return 1;
	}

	char line[256];
	char *current_section = NULL;

	while (fgets(line, sizeof(line), fp))
	{
		/* Process the line (strip comments, trim whitespace) */
		char *processed = config_process_config_line(arena, line);

		if (!processed || processed[0] == '\0')
			continue; /* Skip empty lines */

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
		if (strcmp(current_section, "[sample_rate]") == 0)
		{
			char *value = config_extract_and_trim_value(arena, processed);
			if (value && strstr(processed, "rate"))
			{
				int rate;
				if (sscanf(value, "%d", &rate) == 1 && rate > 0)
				{
					config->default_sample_rate = rate;
					LOG_INFO("Set default sample rate: %d\n", rate);
				}
			}
		}
		else if (strcmp(current_section, "[filters]") == 0)
		{
			/* Parse unified filter entry */
			char class_pattern[256], method_pattern[256], sig_pattern[256];
			int sample_rate;
			char metrics[256] = {0};

			int parsed = sscanf(processed,
			                    "%255[^:]:%255[^:]:%255[^:]:%d:%255s",
			                    class_pattern,
			                    method_pattern,
			                    sig_pattern,
			                    &sample_rate,
			                    metrics);

			if (parsed < 4)
			{
				LOG_ERROR("Invalid filter format: %s\n", processed);
				continue;
			}

			/* Check capacity */
			if (config->unified_filter.num_entries >= MAX_FILTER_ENTRIES)
			{
				LOG_ERROR("Maximum filters reached\n");
				continue;
			}

			/* Add filter entry */
			pattern_filter_entry_t *entry =
			    &config->unified_filter
				 .entries[config->unified_filter.num_entries];

			entry->class_pattern     = arena_strdup(arena, class_pattern);
			entry->method_pattern    = arena_strdup(arena, method_pattern);
			entry->signature_pattern = arena_strdup(arena, sig_pattern);
			entry->sample_rate =
			    sample_rate > 0 ? sample_rate : config->default_sample_rate;
			entry->metric_flags = config_parse_metric_flags(metrics);

			if (!entry->class_pattern || !entry->method_pattern
			    || !entry->signature_pattern)
			{
				LOG_ERROR("Failed to allocate filter strings\n");
				continue;
			}

			config->unified_filter.num_entries++;
			LOG_INFO("Added filter: %s:%s:%s (rate=%d, flags=%u)\n",
			         class_pattern,
			         method_pattern,
			         sig_pattern,
			         entry->sample_rate,
			         entry->metric_flags);
		}
		else if (strcmp(current_section, "[sample_file_location]") == 0)
		{
			char *value = config_extract_and_trim_value(arena, processed);
			if (value && strstr(processed, "path"))
			{
				config->sample_file_path = value;
				LOG_INFO("Set sample file path: %s\n", value);
			}
		}
		else if (strcmp(current_section, "[export]") == 0)
		{
			char *value = config_extract_and_trim_value(arena, processed);
			if (!value)
				continue;

			if (strstr(processed, "method"))
			{
				config->export_method = value;
				LOG_INFO("Set export method: %s\n", value);
			}
			else if (strstr(processed, "interval"))
			{
				int interval;
				if (sscanf(value, "%d", &interval) == 1 && interval > 0)
				{
					config->export_interval = interval;
					LOG_INFO("Set export interval: %d\n", interval);
				}
			}
		}
	}

	fclose(fp);

	LOG_INFO("Config loaded: default_rate=%d, method_filters=%zu, "
	         "path=%s, "
	         "export_method=%s, "
	         "export_interval=%d\n",
	         config->default_sample_rate,
	         config->unified_filter.num_entries,
	         config->sample_file_path ? config->sample_file_path : "NULL",
	         config->export_method ? config->export_method : "NULL",
	         config->export_interval);

	return 0;
}