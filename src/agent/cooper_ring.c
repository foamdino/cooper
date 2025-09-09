/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "cooper_ring.h"

call_stack_sample_t *
sample_alloc(ring_channel_t *ch, uint32_t *out_idx)
{
	uint32_t idx;
	if (ring_pop(&ch->free_ring, &idx) != COOPER_OK)
		return NULL; /* no free slots available */
	if (out_idx)
		*out_idx = idx;
	return (call_stack_sample_t *)ring_store_get(&ch->store, idx);
}

int
sample_publish(ring_channel_t *ch, uint32_t idx)
{
	/* push to ready ring; if full, recycle back to free ring */
	if (ring_push(&ch->ready_ring, idx) != COOPER_OK)
	{
		ring_push(&ch->free_ring, idx);
		return 1;
	}
	return 0;
}

call_stack_sample_t *
sample_consume(ring_channel_t *ch, uint32_t *out_idx)
{
	uint32_t idx;
	if (ring_pop(&ch->ready_ring, &idx) != COOPER_OK)
		return NULL; /* no ready samples */
	if (out_idx)
		*out_idx = idx;
	return (call_stack_sample_t *)ring_store_get(&ch->store, idx);
}

void
sample_release(ring_channel_t *ch, uint32_t idx)
{
	ring_push(&ch->free_ring, idx);
}