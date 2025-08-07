/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "arena_str.h"

/**
 * String utility functions for configuration parsing
 *
 * These functions provide safe string manipulation operations for
 * configuration parsing, with clear ownership semantics and arena-based
 * memory management.
 */

/**
 * Strip trailing comment from a string using arena allocation
 * Preserves '#' characters inside quoted strings
 *
 * @param arena     Pointer to the arena
 * @param str       String to process
 * @return          Newly allocated string without comments, or NULL on error
 */
char *
arena_strip_comment(arena_t *arena, const char *str)
{
	assert(arena != NULL);
	assert(str != NULL);

	if (!arena || !str)
		return NULL;

	/* Find the comment marker, but ignore '#' inside quotes */
	const char *p       = str;
	const char *comment = NULL;
	int in_quotes       = 0;

	while (*p)
	{
		if (*p == '"')
		{
			in_quotes = !in_quotes; /* Toggle quote state */
		}
		else if (*p == '#' && !in_quotes)
		{
			comment = p;
			break;
		}
		p++;
	}

	size_t len = strlen(str);
	/* Adjust len if we have a comment */
	if (comment)
		len = comment - str;

	/* Allocate and copy the substring */
	char *result = arena_alloc(arena, len + 1);
	if (!result)
		return NULL;

	memcpy(result, str, len);
	result[len] = '\0';

	return result;
}

/**
 * Trim whitespace from a string using arena allocation
 *
 * @param arena     Pointer to the arena
 * @param str       String to trim
 * @return          Newly allocated trimmed string, or NULL on error
 */
char *
arena_trim(arena_t *arena, const char *str)
{
	assert(arena != NULL);
	assert(str != NULL);

	if (!arena || !str)
		return NULL;

	/* Skip leading whitespace */
	while (isspace((unsigned char)*str))
		str++;

	/* All whitespace or empty string */
	if (*str == '\0')
	{
		char *result = arena_alloc(arena, 1);
		if (result)
			*result = '\0';
		return result;
	}

	/* Find the end of the string */
	size_t len      = strlen(str);
	const char *end = str + len - 1;

	/* Move backward to find the last non-whitespace character */
	while (end > str && isspace((unsigned char)*end))
		end--;

	/* Calculate the trimmed length */
	size_t trimmed_len = end - str + 1;

	/* Allocate and copy the trimmed string */
	char *result = arena_alloc(arena, trimmed_len + 1);
	if (!result)
		return NULL;

	memcpy(result, str, trimmed_len);
	result[trimmed_len] = '\0';

	return result;
}

/**
 * Duplicate a string using arena memory
 *
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @param max_len   Max length of string
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
char *
arena_strndup(arena_t *arena, const char *str, size_t max_len)
{
	if (!arena || !str)
		return NULL;

	size_t len = strlen(str);
	if (len >= max_len)
		return NULL; /* String is too long */

	/* +1 for null terminator */
	char *dup = arena_alloc(arena, len + 1);
	if (dup)
	{
		memcpy(dup, str, len);
		dup[len] = '\0';
	}
	return dup;
}

/**
 * Duplicate a string using arena memory with default length limit
 *
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
char *
arena_strdup(arena_t *arena, const char *str)
{
	return arena_strndup(arena, str, MAX_STR_LEN);
}