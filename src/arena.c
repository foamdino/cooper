/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>

#include "arena.h"

// Initialize the arena with pre-allocated memory
int arena_init(arena_t *arena, void* memory, size_t size, size_t max_blocks)
{
    if (!memory || size == 0 || max_blocks == 0)
        return 0;
        
    arena->memory = memory;
    arena->total_size = size;
    arena->used = 0;
    
    // Allocate tracking arrays from the pre-allocated memory
    size_t tracking_size = max_blocks * (sizeof(void*) + sizeof(size_t));
    if (tracking_size >= size)
        return 0;
        
    arena->free_blocks = (void**)memory;
    arena->block_sizes = (size_t*)((char*)memory + (max_blocks * sizeof(void*)));
    arena->free_count = 0;
    arena->max_free_blocks = max_blocks;
    
    // Adjust available memory
    arena->memory = (char*)memory + tracking_size;
    arena->total_size -= tracking_size;
    
    return 1;
}

// Allocate memory from the arena
void *arena_alloc(arena_t *arena, size_t size)
{
    if (size == 0)
        return NULL;
    
    // Align size to prevent fragmentation issues
    size = (size + 7) & ~7;  // Align to 8 bytes
    
    // First, check if we have a suitable free block
    for (size_t i = 0; i < arena->free_count; i++) {
        if (arena->block_sizes[i] >= size) {
            void* ptr = arena->free_blocks[i];
            
            // If this block is significantly larger than requested,
            // we could split it (omitted for simplicity)
            
            // Remove this block from free list by moving the last one here
            arena->free_blocks[i] = arena->free_blocks[arena->free_count - 1];
            arena->block_sizes[i] = arena->block_sizes[arena->free_count - 1];
            arena->free_count--;
            
            return ptr;
        }
    }
    
    // No suitable free block, allocate from remaining space
    if (arena->used + size > arena->total_size)
        return NULL;  // Out of memory
        
    void* ptr = (char*)arena->memory + arena->used;
    arena->used += size;
    
    return ptr;
}

// Free memory back to the arena
int arena_free(arena_t *arena, void *ptr, size_t size) 
{
    if (!ptr || size == 0)
        return 0;
        
    // Align size to match allocation
    size = (size + 7) & ~7;
    
    // Check if we can track more free blocks
    if (arena->free_count >= arena->max_free_blocks)
        return 0;
        
    // Add to free list
    arena->free_blocks[arena->free_count] = ptr;
    arena->block_sizes[arena->free_count] = size;
    arena->free_count++;
    
    return 1;
}