/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_STR_H
#define ARENA_STR_H

#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "arena.h"

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
static char *arena_strip_comment(arena_t *arena, const char *str)
{
    assert(arena != NULL);
    assert(str != NULL);
    
    if (!arena || !str)
        return NULL;
    
    /* Find the comment marker, but ignore '#' inside quotes */
    const char *p = str;
    const char *comment = NULL;
    int in_quotes = 0;
    
    while (*p) {
        if (*p == '"') {
            in_quotes = !in_quotes; /* Toggle quote state */
        } else if (*p == '#' && !in_quotes) {
            comment = p;
            break;
        }
        p++;
    }
    
    size_t len;
    if (comment) {
        len = comment - str;
    } else {
        len = strlen(str);
    }
    
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
static char *arena_trim(arena_t *arena, const char *str)
{
    assert(arena != NULL);
    assert(str != NULL);
    
    if (!arena || !str)
        return NULL;
    
    /* Skip leading whitespace */
    while (isspace((unsigned char)*str))
        str++;
    
    /* All whitespace or empty string */
    if (*str == '\0') {
        char *result = arena_alloc(arena, 1);
        if (result)
            *result = '\0';
        return result;
    }
    
    /* Find the end of the string */
    size_t len = strlen(str);
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
 * Extract value part from a "key = value" string and trim it, using arena allocation
 * Also handles quoted values by removing surrounding quotes
 * 
 * @param arena     Pointer to the arena
 * @param line      Line to process
 * @return          Extracted and trimmed value, or NULL if no value found or on error
 */
static char *arena_extract_and_trim_value(arena_t *arena, const char *line)
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
    if (trimmed_len >= 2 && trimmed_value[0] == '"' && trimmed_value[trimmed_len - 1] == '"') {
        /* Allocate space for string without quotes */
        char *unquoted = arena_alloc(arena, trimmed_len - 1); /* -1 because we're removing 2 quotes but need null terminator */
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
static char *arena_process_config_line(arena_t *arena, const char *line)
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
 * Duplicate a string using arena memory
 * 
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
static inline char *arena_strdup(arena_t *arena, const char *str)
{
    if (!arena || !str) return NULL;
    
    size_t len = strlen(str);
    /* +1 for null terminator */
    char *dup = arena_alloc(arena, len + 1);
    if (dup) {
        memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}

#endif /* ARENA_H */