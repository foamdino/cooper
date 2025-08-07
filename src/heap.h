/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>

#include "arena.h"

/* Generic comparison function type */
typedef int (*heap_compare_fn)(const void *a, const void *b);

typedef struct min_heap min_heap_t;

/* Generic min-heap structure */
struct min_heap
{
	void **elements;
	size_t capacity;
	size_t size;
	heap_compare_fn compare;
};

/* External API */
min_heap_t *min_heap_create(arena_t *arena, size_t capacity, heap_compare_fn compare);
int min_heap_insert_or_replace(min_heap_t *heap, void *element);

/* Generic heap operations */
static inline size_t
heap_parent(size_t i)
{
	return (i - 1) / 2;
}
static inline size_t
heap_left(size_t i)
{
	return 2 * i + 1;
}
static inline size_t
heap_right(size_t i)
{
	return 2 * i + 2;
}

/* Swap two elements */
static inline void
heap_swap(min_heap_t *heap, size_t i, size_t j)
{
	void *temp        = heap->elements[i];
	heap->elements[i] = heap->elements[j];
	heap->elements[j] = temp;
}

#endif /* HEAP_H */