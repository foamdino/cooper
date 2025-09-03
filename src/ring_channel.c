/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ring_channel.h"

int
ring_channel_init(ring_channel_t *ch, uint32_t capacity, uint32_t elem_sz)
{
	if (ring_store_init(&ch->store, capacity, elem_sz) != 0)
		return 0;
	if (ring_init(&ch->free_ring, capacity) != 0)
		return 0;
	if (ring_init(&ch->ready_ring, capacity) != 0)
		return 0;

	/* populate freelist with all indices */
	for (uint32_t i = 0; i < capacity; i++)
		ring_push(&ch->free_ring, i);

	return 1;
}

void
ring_channel_free(ring_channel_t *ch)
{
	ring_store_free(&ch->store);
	ring_free(&ch->free_ring);
	ring_free(&ch->ready_ring);
}