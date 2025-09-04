/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RING_STORE_H
#define RING_STORE_H

#include <stdint.h>
#include <stdlib.h>

typedef struct ring_store ring_store_t;

struct ring_store
{
	void *base;        /**< raw contiguous memory */
	uint32_t capacity; /**< number of elements */
	uint32_t elem_sz;  /**< size of an element */
};

int ring_store_init(ring_store_t *s, uint32_t capacity, uint32_t elem_sz);

void ring_store_free(ring_store_t *s);

void *ring_store_get(ring_store_t *s, uint32_t idx);

#endif /* RING_STORE_H */