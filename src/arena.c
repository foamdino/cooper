/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "arena.h"

/**
 * Initialize a new memory arena
 * 
 * Creates and initializes a memory arena with the specified size and capacity
 * for tracking free blocks. The arena allocates a contiguous block of memory
 * and manages allocations from this block to reduce the overhead of frequent
 * small allocations.
 * 
 * @param name          Descriptive name for the arena (for debugging)
 * @param size          Total size of the memory pool in bytes
 * @param max_blocks    Maximum number of free blocks that can be tracked
 * 
 * @return              Pointer to the initialized arena, or NULL on failure
 */
arena_t *arena_init(const char *name, size_t sz, size_t max_blocks)
{
    if (sz == 0 || max_blocks == 0)
        return NULL;
    
    /* Allocate the arena struct itself */
    arena_t *arena = (arena_t*)malloc(sizeof(arena_t));
    if (!arena)
        return NULL;
    
    /* Copy the name (with truncation if needed) */
    strncpy(arena->name, name ? name : "unnamed", sizeof(arena->name) - 1);
    arena->name[sizeof(arena->name) - 1] = '\0';
    
    /* 
     * Store the allocation size for future reference - this will help
     * with arena cleanup during shutdown 
     */
    arena->alloc_sz = sz;
    
    /* Allocate the memory pool */
    void* memory = malloc(sz);
    if (!memory)
        goto error_cleanup;
    
    arena->memory = memory;
    arena->total_sz = sz;
    arena->used = 0;
    
    /* Allocate tracking arrays from the pre-allocated memory */
    size_t tracking_sz = max_blocks * (sizeof(void*) + sizeof(size_t));
    if (tracking_sz >= sz)
        goto error_cleanup;
        
    arena->free_blocks = (void**)memory;
    arena->block_sizes = (size_t*)((char*)memory + (max_blocks * sizeof(void*)));
    arena->free_count = 0;
    arena->max_free_blocks = max_blocks;
    
    /* Store original memory pointer for cleanup */
    arena->original_memory = memory;
    
    /* Adjust available memory */
    arena->memory = (char*)memory + tracking_sz;
    arena->total_sz -= tracking_sz;
    
    return arena;

error_cleanup:
    if (memory)
        free(memory);

    if (arena)
        free(arena);

    return NULL;
}

/**
 * Allocate memory from the arena
 * 
 * This function attempts to allocate memory from the arena's pool. It first tries to
 * reuse a previously freed block of adequate size, and if none is available, allocates
 * from the remaining arena space. Each allocation includes a hidden header that stores
 * the size and a magic number for validation.
 * 
 * Memory is aligned to 8-byte boundaries and always zero-initialized for safety.
 * 
 * @param arena         Pointer to the arena
 * @param size          Number of bytes to allocate
 * 
 * @return              Pointer to the allocated memory, or NULL if:
 *                      - arena is NULL
 *                      - size is 0
 *                      - not enough memory is available in the arena
 */
void *arena_alloc(arena_t *arena, size_t sz)
{
    assert(arena != NULL);
    assert(sz > 0);
    
    if (sz == 0)
        return NULL;
    
    /* Calculate total size needed including header */
    size_t header_size = sizeof(block_header_t);
    size_t total_size = sz + header_size;
    
    /* Align total size to prevent fragmentation issues */
    total_size = (total_size + 7) & ~7;  /* Align to 8 bytes */
    
    /* First, check if we have a suitable free block */
    for (size_t i = 0; i < arena->free_count; i++) {
        if (arena->block_sizes[i] >= total_size) {
            void* block = arena->free_blocks[i];
            
            /* Remove this block from free list by moving the last one here */
            arena->free_blocks[i] = arena->free_blocks[arena->free_count - 1];
            arena->block_sizes[i] = arena->block_sizes[arena->free_count - 1];
            arena->free_count--;
            
            /* Initialize block header */
            block_header_t *header = (block_header_t*)block;
            header->block_sz = sz;
            header->total_block_sz = total_size;
            header->magic = ARENA_BLOCK_MAGIC;
            
            /* Return pointer to user data (after the header) */
            void *user_ptr = (char*)block + header_size;
            memset(user_ptr, 0, sz);
            return user_ptr;
        }
    }
    
    /* No suitable free block, allocate from remaining space */
    if (arena->used + total_size > arena->total_sz)
        return NULL;  /* Out of memory */
        
    void* block = (char*)arena->memory + arena->used;
    arena->used += total_size;
    
    /* Initialize block header */
    block_header_t *header = (block_header_t*)block;
    header->block_sz = sz;
    header->total_block_sz = total_size;
    header->magic = ARENA_BLOCK_MAGIC;
    
    /* Return pointer to user data (after the header) */
    void *user_ptr = (char*)block + header_size;
    memset(user_ptr, 0, sz);
    return user_ptr;
}

/**
 * Free memory back to the arena
 * 
 * Returns a previously allocated block to the arena's free list for potential reuse.
 * The function validates that the pointer was allocated from this arena by checking
 * its header magic number. The size is automatically retrieved from the block header.
 * 
 * Note: This doesn't actually release memory back to the system, but makes it available
 * for future allocations from the same arena.
 * 
 * @param arena         Pointer to the arena
 * @param ptr           Pointer to memory previously allocated with arena_alloc
 * 
 * @return              1 on success, 0 on failure (NULL pointer, invalid pointer, 
 *                      or arena free list full)
 */
int arena_free(arena_t *arena, void *ptr) 
{
    assert(arena != NULL);
    
    if (!ptr)
        return 0;
        
    
    /* Get block header by going back from the user pointer */
    block_header_t *header = (block_header_t*)((char*)ptr - sizeof(block_header_t));
    
    /* Validate the header */
    if (header->magic != ARENA_BLOCK_MAGIC) 
    {
        /* Invalid pointer or corrupted memory */
        return 0;
    }
    
    /* Check if we can track more free blocks */
    if (arena->free_count >= arena->max_free_blocks)
        return 0;
        
    /* Add to free list */
    arena->free_blocks[arena->free_count] = header; /* Store pointer to header, not user data */
    arena->block_sizes[arena->free_count] = header->total_block_sz;
    arena->free_count++;
    
    return 1;
}

/**
 * Destroy an arena and free all associated memory
 * 
 * Releases all memory managed by the arena, including the arena structure itself.
 * This invalidates all memory previously allocated from this arena, and the arena
 * pointer should not be used after this call.
 * 
 * @param arena         Pointer to the arena to destroy
 */
void arena_destroy(arena_t *arena)
{
    assert(arena != NULL);
    
    if (!arena)
        return;
    
    /* Free the original memory we allocated directly in arena_init */
    if (arena->original_memory) 
    {
        free(arena->original_memory);
        arena->original_memory = NULL;
        arena->memory = NULL;
    }
    
    /* Free the arena struct itself */
    free(arena);
}

/**
 * Reset the arena
 * 
 * @param arena         Pointer to the arena to reset
 */
void arena_reset(arena_t *arena)
{
    assert(arena != NULL);

    if (!arena)
        return;

    arena->used = 0;
    arena->free_count = 0;

    /* Clear free block tracking */
    memset(arena->free_blocks, 0, arena->max_free_blocks * sizeof(void*));
    memset(arena->block_sizes, 0, arena->max_free_blocks * sizeof(size_t));
}

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
    const char *name, size_t size, size_t max_blocks)
{
    arena_node_t *node = malloc(sizeof(arena_node_t));
    if (!node)
        return NULL;

    /* Initialize the arena */
    arena_t *arena = arena_init(name, size, max_blocks);
    if (!arena) 
    {
        free(node);
        return NULL;
    }

    /* Set up the node */
    strncpy(node->name, name, sizeof(node->name) - 1);
    node->name[sizeof(node->name) - 1] = '\0';
    node->arena = arena;
    node->sz = size;
    node->next = NULL;

    /* Add to the list */
    if (*tail) 
    {
        /* List is not empty, append to tail */
        node->prev = *tail;
        (*tail)->next = node;
        *tail = node;
    } 
    else 
    {
        /* List is empty, update both head and tail */
        node->prev = NULL;
        *head = node;
        *tail = node;
    }

    return arena;
}

/**
* Find an arena by name
* 
* @param head      Head of the arena list
* @param name      Name of the arena to find
* 
* @return          Pointer to the found arena, or NULL if not found
*/
arena_t *find_arena(arena_node_t *head, const char *name) {
    arena_node_t *node = head;
    while (node) 
    {
        if (strcmp(node->name, name) == 0)
            return node->arena;

        node = node->next;
    }
    return NULL;
}

/**
* Destroy all arenas in the list
* 
* @param head      Pointer to the head pointer of the list (modified)
* @param tail      Pointer to the tail pointer of the list (modified)
*/
void destroy_all_arenas(arena_node_t **head, arena_node_t **tail) {
    arena_node_t *node = *head;

    while (node)
    {
        arena_node_t *next = node->next;
        if (node->arena)
            arena_destroy(node->arena);
        
        free(node);
        node = next;
    }

    *head = NULL;
    *tail = NULL;
}