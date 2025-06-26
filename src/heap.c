/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "heap.h"

/* Initialize heap with arena allocation */
static min_heap_t *min_heap_create(arena_t *arena, size_t capacity, size_t element_size, heap_compare_fn compare) 
{
    min_heap_t *heap = arena_alloc(arena, sizeof(min_heap_t));
    heap->elements = arena_alloc(arena, sizeof(void*) *capacity);
    heap->element_size = element_size;
    heap->capacity = capacity;
    heap->size = 0;
    heap->compare = compare;
    return heap;
}

/* Generic heap operations */
static inline size_t heap_parent(size_t i) { return (i - 1) / 2; }
static inline size_t heap_left(size_t i) { return 2 * i + 1; }
static inline size_t heap_right(size_t i) { return 2 * i + 2; }

/* Swap two elements */
static inline void
heap_swap(min_heap_t *heap, size_t i, size_t j) 
{
    void* temp = heap->elements[i];
    heap->elements[i] = heap->elements[j];
    heap->elements[j] = temp;
}

/* Bubble up element at index */
static void
min_heap_bubble_up(min_heap_t *heap, size_t idx) 
{
    while (idx > 0) 
    {
        size_t parent_idx = heap_parent(idx);
        if (heap->compare(heap->elements[idx], heap->elements[parent_idx]) >= 0)
            break;
        
        heap_swap(heap, idx, parent_idx);
        idx = parent_idx;
    }
}

/* Bubble down element at index */
static void
min_heap_bubble_down(min_heap_t *heap, size_t idx) {
    while (heap_left(idx) < heap->size) 
    {
        size_t min_child = heap_left(idx);
        size_t right = heap_right(idx);
        
        if (right < heap->size && heap->compare(heap->elements[right], heap->elements[min_child]) < 0)
            min_child = right;
        
        if (heap->compare(heap->elements[idx], heap->elements[min_child]) <= 0)
            break;
        
        heap_swap(heap, idx, min_child);
        idx = min_child;
    }
}

/* Insert element or replace minimum if heap is full */
static int
min_heap_insert_or_replace(min_heap_t *heap, void *element) {
    if (heap->size < heap->capacity) 
    {
        /* Heap not full, add element */
        heap->elements[heap->size] = element;
        min_heap_bubble_up(heap, heap->size);
        heap->size++;
        return 1;
    } 
    else if (heap->compare(element, heap->elements[0]) > 0) 
    {
        /* Element is larger than min, replace it */
        heap->elements[0] = element;
        min_heap_bubble_down(heap, 0);
        return 1;
    }
    return 0; /* Element didn't make it into top N */
}