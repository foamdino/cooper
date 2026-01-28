/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_H
#define ARENA_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdio.h>

typedef struct arena arena_t;
typedef struct arena_config arena_config_t;

struct arena_config
{
	size_t id;        /**< Arena id */
	const char *name; /**< Arena name */
	size_t size;      /**< Arena size in bytes */
};

struct arena
{
	void *memory;          /* Pre-allocated memory buffer */
	void *original_memory; /* Original pointer returned by mmap */
	size_t requested_sz;   /* Requested size during init */
	size_t alloc_sz;       /* Total allocation size, used for cleanup */
	size_t total_sz;       /* Total size of memory pool - should be page aligned */
	size_t used;           /* Currently used bytes */
	char name[32];         /* Name of the arena for debugging */
};

/**
 * Initialize a new memory arena
 *
 * @param name          Descriptive name for the arena (for debugging)
 * @param sz            Total size of the memory pool in bytes
 *
 * @return              Pointer to the initialized arena, or NULL on failure
 */
arena_t *arena_init(const char *name, size_t sz);

/**
 * Allocate memory from the arena
 *
 * This function attempts to allocate memory from the arena.
 *
 * @param arena         Pointer to the arena
 * @param sz            Number of bytes to allocate
 *
 * @return              Pointer to the allocated memory, or NULL if allocation failed
 */
void *arena_alloc(arena_t *arena, size_t sz);

void *arena_alloc_aligned(arena_t *arena, size_t size, size_t alignment);

/**
 * Destroy an arena and free all associated memory
 *
 * Releases all memory managed by the arena, including the arena structure itself.
 * After this call, the arena pointer should not be used.
 *
 * @param arena         Pointer to the arena to destroy
 */
void arena_destroy(arena_t *arena);

/**
 * Reset the arena
 *
 * @param arena         Pointer to the arena to reset
 */
void arena_reset(arena_t *arena);

/**
 * Destroy all arenas in the list
 *
 */
void destroy_all_arenas(arena_t *arenas[], size_t max);

#endif /* ARENA_H */
