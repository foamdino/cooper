/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ring_store.h"

int
ring_store_init(ring_store_t *s, uint32_t capacity, uint32_t elem_sz)
{
	// TODO perhaps mmap here - but calloc is simple
	s->base = calloc(capacity, elem_sz);
	if (!s->base)
		return 1;

	s->flags = calloc(capacity, sizeof(uint8_t));
	if (!s->flags)
	{
		free(s->base);
		s->base = NULL;
		return 1;
	}

	s->capacity = capacity;
	s->elem_sz  = elem_sz;
	return 0;
}

void
ring_store_free(ring_store_t *s)
{
	if (s->base)
		free(s->base);
	if (s->flags)
		free(s->flags);

	s->base     = NULL;
	s->flags    = NULL;
	s->capacity = 0;
	s->elem_sz  = 0;
}

void *
ring_store_get(ring_store_t *s, uint32_t idx)
{
	return (uint8_t *)s->base + (size_t)idx * s->elem_sz;
}

uint8_t *
ring_store_get_flag(ring_store_t *s, uint32_t idx)
{
	if (!s->flags)
		return NULL;
	return &s->flags[idx];
}