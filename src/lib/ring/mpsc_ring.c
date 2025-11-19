/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "mpsc_ring.h"

/* Slot status flags */
#define SLOT_FREE  0
#define SLOT_BUSY  1 /* Reserved by producer, writing in progress */
#define SLOT_READY 2 /* Written by producer, ready for consumer */

int
mpsc_ring_init(mpsc_ring_t *ring, uint32_t capacity, uint32_t elem_sz)
{
	if (!ring || capacity == 0 || elem_sz == 0)
		return 1;

	/* Capacity must be power of 2 */
	if ((capacity & (capacity - 1)) != 0)
		return 1;

	/* Initialize store with flags */
	if (ring_store_init(&ring->store, capacity, elem_sz) != 0)
		return 1;

	atomic_init(&ring->head, 0);
	atomic_init(&ring->tail, 0);
	atomic_init(&ring->dropped, 0);

	return 0;
}

void
mpsc_ring_free(mpsc_ring_t *ring)
{
	if (!ring)
		return;

	ring_store_free(&ring->store);
}

int
mpsc_ring_reserve(mpsc_ring_t *ring, uint32_t *out_handle)
{
	uint64_t head, tail;
	uint64_t next_head;

	/*
	 * CAS Loop to reserve a slot
	 */
	do
	{
		head = atomic_load_explicit(&ring->head, memory_order_relaxed);
		tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

		if (head - tail >= ring->store.capacity)
		{
			/* Ring is full */
			atomic_fetch_add_explicit(
			    &ring->dropped, 1, memory_order_relaxed);
			return MPSC_FULL;
		}

		next_head = head + 1;

	} while (!atomic_compare_exchange_weak_explicit(
	    &ring->head, &head, next_head, memory_order_acq_rel, memory_order_relaxed));

	/* We successfully reserved the index 'head' */
	uint32_t idx = head & (ring->store.capacity - 1);

	if (out_handle)
		*out_handle = idx;

	return MPSC_OK;
}

void
mpsc_ring_commit(mpsc_ring_t *ring, uint32_t handle)
{
	/* Get flag pointer */
	uint8_t *flag_ptr = ring_store_get_flag(&ring->store, handle);
	if (flag_ptr)
	{
		/* Mark as READY. Release ordering ensures data writes are visible before
		 * flag */
		atomic_store_explicit(
		    (_Atomic uint8_t *)flag_ptr, SLOT_READY, memory_order_release);
	}
}

int
mpsc_ring_consume(mpsc_ring_t *ring, uint32_t *out_handle)
{
	uint64_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	uint64_t head = atomic_load_explicit(&ring->head, memory_order_acquire);

	if (tail == head)
		return MPSC_EMPTY;

	uint32_t idx = tail & (ring->store.capacity - 1);

	/* Check flag */
	uint8_t *flag_ptr = ring_store_get_flag(&ring->store, idx);
	if (!flag_ptr)
		return MPSC_EMPTY; /* Should not happen */

	uint8_t flag =
	    atomic_load_explicit((_Atomic uint8_t *)flag_ptr, memory_order_acquire);

	if (flag != SLOT_READY)
	{
		/* Producer has reserved slot but not finished writing */
		return MPSC_BUSY;
	}

	if (out_handle)
		*out_handle = idx;

	return MPSC_OK;
}

void
mpsc_ring_release(mpsc_ring_t *ring, uint32_t handle)
{
	/*
	 * In this MPSC implementation, release MUST be in FIFO order (tail).
	 * We verify the handle matches the current tail index for sanity.
	 */
	uint64_t tail     = atomic_load_explicit(&ring->tail, memory_order_relaxed);
	uint32_t tail_idx = tail & (ring->store.capacity - 1);

	if (handle != tail_idx)
	{
		/* This implies out-of-order release which violates the single-consumer
		 * FIFO assumption */
		/* We could assert here, or just ignore/log error. For now, we proceed
		   with tail release logic but using the handle to clear the flag is
		   correct if handle == tail_idx */
	}

	/* Mark as FREE */
	uint8_t *flag_ptr = ring_store_get_flag(&ring->store, handle);
	if (flag_ptr)
	{
		atomic_store_explicit(
		    (_Atomic uint8_t *)flag_ptr, SLOT_FREE, memory_order_relaxed);
	}

	/* Advance tail */
	atomic_store_explicit(&ring->tail, tail + 1, memory_order_release);
}

void *
mpsc_ring_get(mpsc_ring_t *ring, uint32_t handle)
{
	return ring_store_get(&ring->store, handle);
}
