/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_STR_H
#define ARENA_STR_H

#include <ctype.h>
#include <assert.h>
#include <string.h>

#include "arena.h"

/* Maximum length for general-purpose string operations */
#ifndef MAX_STR_LEN
#define MAX_STR_LEN 4096
#endif

/**
 * Strip trailing comment from a string using arena allocation
 * Preserves '#' characters inside quoted strings
 * 
 * @param arena     Pointer to the arena
 * @param str       String to process
 * @return          Newly allocated string without comments, or NULL on error
 */
char *arena_strip_comment(arena_t *arena, const char *str);

/**
 * Trim whitespace from a string using arena allocation
 * 
 * @param arena     Pointer to the arena
 * @param str       String to trim
 * @return          Newly allocated trimmed string, or NULL on error
 */
char *arena_trim(arena_t *arena, const char *str);

/**
 * Duplicate a string using arena memory
 * 
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @param max_len   Max length of string
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
char *arena_strndup(arena_t *arena, const char *str, size_t max_len);

/**
 * Duplicate a string using arena memory with default length limit
 * 
 * @param arena     Pointer to the arena
 * @param str       String to duplicate
 * @return          Pointer to the duplicated string in arena memory, or NULL on failure
 */
char *arena_strdup(arena_t *arena, const char *str);

#endif /* ARENA_H */