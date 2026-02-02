/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "arena.h"

/**
 * Initialize a new memory arena
 *
 * Creates and initializes a memory arena with the specified size
 * The arena allocates a contiguous block of memory
 * and manages allocations from this block to reduce the overhead of frequent
 * small allocations.
 *
 * @param name          Descriptive name for the arena (for debugging)
 * @param size          Total size of the memory pool in bytes
 *
 * @return              Pointer to the initialized arena, or NULL on failure
 */
arena_t *
arena_init(const char *name, size_t sz)
{
	if (sz == 0)
		return NULL;

	/* Allocate the arena struct itself */
	arena_t *arena = (arena_t *)malloc(sizeof(arena_t));
	if (!arena)
		return NULL;

	/* Copy the name (with truncation if needed) */
	strncpy(arena->name, name ? name : "unnamed", sizeof(arena->name) - 1);
	arena->name[sizeof(arena->name) - 1] = '\0';

	/* Round up size to page boundary for mmap */
	size_t page_sz = sysconf(_SC_PAGESIZE);
	size_t mmap_sz = (sz + page_sz - 1) & ~(page_sz - 1);

	/* Allocate the memory pool using mmap */
	void *memory = mmap(
	    NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (memory == MAP_FAILED)
		goto error_cleanup;

	/*
	 * Store the allocation size for future reference - this will help
	 * with arena cleanup during shutdown
	 */
	arena->alloc_sz        = mmap_sz;
	arena->requested_sz    = sz;
	arena->total_sz        = mmap_sz;
	arena->original_memory = memory;
	arena->used            = 0;
	arena->memory          = memory;

	return arena;

error_cleanup:
	if (memory && memory != MAP_FAILED)
		munmap(memory, mmap_sz);

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
void *
arena_alloc(arena_t *arena, size_t sz)
{
	assert(arena != NULL);
	assert(sz > 0);

	if (sz == 0)
		return NULL;

	/* Align size to prevent fragmentation issues */
	size_t aligned_sz = (sz + 7) & ~7; /* Align to 8 bytes */

	/* No suitable free block, allocate from remaining space */
	if (arena->used + aligned_sz > arena->total_sz)
	{
		fprintf(stderr,
		        "arena_alloc: insufficient space in %s: need=%zu available=%zu "
		        "used=%zu total=%zu\n",
		        arena->name,
		        aligned_sz,
		        arena->total_sz - arena->used,
		        arena->used,
		        arena->total_sz);
		return NULL; /* Out of memory */
	}

	void *ptr = (char *)arena->memory + arena->used;
	arena->used += aligned_sz;

	/* Zero initial mem */
	memset(ptr, 0, sz);

	return ptr;
}

/**
 *
 * Before alignment:
 * |--------used--------|xxxxx|<-requested size->|-----free-----|
 *                      ^
 *                      current position (unaligned)
 *
 * After alignment:
 * |--------used--------|xxxxx|padding|<-requested size->|-----free-----|
 *                                    ^
 *                                    aligned position
 */
void *
arena_alloc_aligned(arena_t *arena, size_t size, size_t alignment)
{
	assert(arena != NULL);
	assert(alignment > 0 && (alignment & (alignment - 1)) == 0); /* Power of 2 */

	/* Calculate padding needed for alignment */
	uintptr_t current = (uintptr_t)((char *)arena->memory + arena->used);
	uintptr_t aligned = (current + alignment - 1) & ~(alignment - 1);
	size_t padding    = aligned - current;

	/* Check if we have enough space */
	if (arena->used + padding + size > arena->total_sz)
		return NULL;

	/* Apply padding before allocation */
	arena->used += padding;

	/* Now allocate normally */
	return arena_alloc(arena, size);
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
void
arena_destroy(arena_t *arena)
{
	assert(arena != NULL);

	if (!arena)
		return;

	/* Unmap the memory instead of free */
	if (arena->original_memory && arena->original_memory != MAP_FAILED)
		munmap(arena->original_memory, arena->alloc_sz);

	/* Free the arena struct itself */
	free(arena);
}

/**
 * Reset the arena
 *
 * @param arena         Pointer to the arena to reset
 */
void
arena_reset(arena_t *arena)
{
	assert(arena != NULL);

	if (!arena)
		return;

	arena->used = 0;
}

/**
 * Destroy all arenas in the list
 *
 */
void
destroy_all_arenas(arena_t *arenas[], size_t max)
{
	for (size_t i = 0; i < max; i++)
	{
		if (arenas[i] != NULL)
			arena_destroy(arenas[i]);
	}
}