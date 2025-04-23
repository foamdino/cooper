/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_H
#define ARENA_H

#include <stdint.h>
#include <stddef.h>

/**
 * Magic number for block validation
 * 
 * This specific value is used to verify that a pointer passed to arena_free()
 * was actually allocated from the arena. This helps detect invalid frees and
 * memory corruption.
 */
#define ARENA_BLOCK_MAGIC 0xC00BEEF5

typedef struct arena arena_t;
typedef struct block_header block_header_t;
typedef struct arena_node arena_node_t;
typedef struct arena_config arena_config_t;

struct arena_config
{
    const char *name;        /**< Arena name */
    size_t size;             /**< Arena size in bytes */
    size_t block_count;      /**< Maximum number of free blocks to track */
};

struct block_header 
{
    size_t block_sz; /**< Size of user data (excluding header) */
    size_t total_block_sz; /**< Size of block user data + header */
    uint32_t magic; /**< Magic number used for validation */
};

struct arena_node
{
    arena_t *arena;            /**< The actual arena */
    char name[32];             /**< Name of the arena (for lookup) */
    size_t sz;               /**< Size of the arena */
    arena_node_t *next;   /**< Next node in the list */
    arena_node_t *prev;   /**< Previous node in the list */
};

struct arena 
{
    void* memory;          /* Pre-allocated memory buffer */
    void* original_memory; /* Original pointer returned by malloc */
    size_t alloc_sz;     /* Total allocation size */
    size_t total_sz;     /* Total size of memory pool */
    size_t used;           /* Currently used bytes */
    void** free_blocks;    /* Array of pointers to free blocks */
    size_t* block_sizes;   /* Corresponding sizes of free blocks */
    size_t free_count;     /* Number of free blocks available */
    size_t max_free_blocks; /* Maximum number of free blocks we can track */
    char name[32];         /* Name of the arena for debugging */
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
 * Create a new arena, initialize it and add it to a list
 * 
 * @param head      Pointer to the head pointer of the list (modified)
 * @param tail      Pointer to the tail pointer of the list (modified)
 * @param name      Name of the arena
 * @param size      Size of the arena
 * @param max_blocks Maximum number of free blocks to track
 * 
 * @return          Pointer to the created arena, or NULL on failure
 */
arena_t *create_arena(arena_node_t **head, arena_node_t **tail, 
    const char *name, size_t size, size_t max_blocks);

/**
* Find an arena by name
* 
* @param head      Head of the arena list
* @param name      Name of the arena to find
* 
* @return          Pointer to the found arena, or NULL if not found
*/
arena_t *find_arena(arena_node_t *head, const char *name);

/**
 * Destroy all arenas in the list
 * 
 * @param head      Pointer to the head pointer of the list (modified)
 * @param tail      Pointer to the tail pointer of the list (modified)
 */
void destroy_all_arenas(arena_node_t **head, arena_node_t **tail);

#endif /* ARENA_H */
 