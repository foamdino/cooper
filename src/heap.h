/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HEAP_H
#define HEAP_H

#include <unistd.h>

#include "arena.h"

/* Generic comparison function type */
typedef int (*heap_compare_fn)(const void* a, const void* b);

typedef struct min_heap min_heap_t;

/* Generic min-heap structure */
struct min_heap 
{
    void **elements;
    size_t element_size;
    size_t capacity;
    size_t size;
    heap_compare_fn compare;
};

#endif /* HEAP_H */