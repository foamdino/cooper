/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RING_H
#define RING_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct ring ring_t;

struct ring
{
	uint32_t *slots;            /**< we store handles to the data */
	uint32_t capacity;          /**< must be power of two for fast masking */
	_Atomic uint32_t write_idx; /**< producer advances */
	_Atomic uint32_t read_idx;  /**< consumer advances */
	_Atomic uint64_t dropped;   /**< samples overwritten/dropped */
};

int ring_init(ring_t *r, uint32_t capacity);

void ring_free(ring_t *r);

int ring_push(ring_t *r, uint32_t handle);

int ring_pop(ring_t *r, uint32_t *out);

#endif /* RING_H */