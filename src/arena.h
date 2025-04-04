/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>

typedef struct arena arena_t;

struct arena {
    void* memory;          /* Pre-allocated memory buffer */
    void* original_memory; /* Original pointer returned by malloc */
    size_t alloc_size;     /* Total allocation size */
    size_t total_size;     /* Total size of memory pool */
    size_t used;           /* Currently used bytes */
    void** free_blocks;    /* Array of pointers to free blocks */
    size_t* block_sizes;   /* Corresponding sizes of free blocks */
    size_t free_count;     /* Number of free blocks available */
    size_t max_free_blocks; /* Maximum number of free blocks we can track */
    char name[32];         /* Name of the arena for debugging */
};

arena_t *arena_init(const char *name, size_t size, size_t max_blocks);
void *arena_alloc(arena_t *arena, size_t size);
int arena_free(arena_t *arena, void *ptr, size_t size);
void arena_destroy(arena_t *arena);

#endif /* ARENA_H */
 