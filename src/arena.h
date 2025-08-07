/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_H
#define ARENA_H

#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/**
 * Magic number for block validation
 *
 * This specific value is used to verify that a pointer passed to arena_free()
 * was actually allocated from the arena. This helps detect invalid frees and
 * memory corruption.
 */
#define ARENA_BLOCK_MAGIC 0xF0A3D900

typedef struct arena arena_t;
typedef struct block_header block_header_t;
typedef struct arena_config arena_config_t;

struct arena_config
{
	size_t id;          /**< Arena id */
	const char *name;   /**< Arena name */
	size_t size;        /**< Arena size in bytes */
	size_t block_count; /**< Maximum number of free blocks to track */
};

struct block_header
{
	size_t block_sz;       /**< Size of user data (excluding header) */
	size_t total_block_sz; /**< Size of block user data + header */
	uint32_t magic;        /**< Magic number used for validation */
};
struct arena
{
	void *memory;           /* Pre-allocated memory buffer */
	void *original_memory;  /* Original pointer returned by malloc */
	size_t requested_sz;    /* Requested size during init */
	size_t alloc_sz;        /* Total allocation size, used for cleanup */
	size_t available_sz;    /* Available (total - tracking metadata)  */
	size_t total_sz;        /* Total size of memory pool - should be page aligned */
	size_t used;            /* Currently used bytes */
	void **free_blocks;     /* Array of pointers to free blocks */
	size_t *block_sizes;    /* Corresponding sizes of free blocks */
	size_t free_count;      /* Number of free blocks available */
	size_t max_free_blocks; /* Maximum number of free blocks we can track */
	char name[32];          /* Name of the arena for debugging */
};

/**
 * Initialize a new memory arena
 *
 * @param name          Descriptive name for the arena (for debugging)
 * @param sz            Total size of the memory pool in bytes
 * @param max_blocks    Maximum number of free blocks that can be tracked
 *
 * @return              Pointer to the initialized arena, or NULL on failure
 */
arena_t *arena_init(const char *name, size_t sz, size_t max_blocks);

/**
 * Allocate memory from the arena
 *
 * This function attempts to allocate memory from the arena's pool. It first tries to
 * reuse a previously freed block of adequate size, and if none is available, allocates
 * from the remaining arena space. Each allocation includes a hidden header that tracks
 * the size and validates the block.
 *
 * @param arena         Pointer to the arena
 * @param sz            Number of bytes to allocate
 *
 * @return              Pointer to the allocated memory, or NULL if allocation failed
 */
void *arena_alloc(arena_t *arena, size_t sz);

void *arena_alloc_aligned(arena_t *arena, size_t size, size_t alignment);

/**
 * Free memory back to the arena
 *
 * Returns a previously allocated block to the arena's free list for potential reuse.
 * The function validates that the pointer was allocated from this arena by checking
 * its header magic number. The size is automatically retrieved from the block header.
 *
 * @param arena         Pointer to the arena
 * @param ptr           Pointer to memory previously allocated with arena_alloc
 *
 * @return              1 on success, 0 on failure (invalid pointer or arena full)
 */
int arena_free(arena_t *arena, void *ptr);

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
