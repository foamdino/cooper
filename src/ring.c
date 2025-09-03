/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ring.h"

/**
 * @brief Initializes a ring buffer.
 *
 * This function sets up a ring buffer instance by linking it to a pre-allocated
 * storage array and setting the capacity. It also initializes the read and write
 * indices to zero. The capacity must be a power of two for the masking
 * operation to work correctly.
 *
 * @param r A pointer to the ring buffer instance to be initialized.
 * @param capacity The maximum number of elements the ring buffer can hold.
 * This value must be a power of two.
 */
int
ring_init(ring_t *r, uint32_t capacity)
{
	/* must be power of two */
	if ((capacity & (capacity - 1)) != 0)
		return 1;

	r->slots = calloc(capacity, sizeof(uint32_t));
	if (!r->slots)
		return 1;
	r->capacity = capacity;
	atomic_store(&r->write_idx, 0);
	atomic_store(&r->read_idx, 0);
	atomic_store(&r->dropped, 0);

	return 0;
}

void
ring_free(ring_t *r)
{
	free(r->slots);
	r->slots    = NULL;
	r->capacity = 0;
}

/**
 * @brief Pushes a handle onto the ring buffer.
 *
 * This function attempts to add a new handle to the ring buffer. It is a
 * non-blocking operation. If the buffer is full, the operation fails and the
 * function returns a non-zero value, and the dropped count is incremented.
 * It uses relaxed and acquire/release memory orders to ensure correct
 * synchronization with the consumer thread.
 *
 * @param r A pointer to the ring buffer instance.
 * @param handle The 32-bit handle to be pushed onto the buffer.
 * @return 0 on success, 1 if the buffer is full.
 */
int
ring_push(ring_t *r, uint32_t handle)
{
	uint32_t w    = atomic_load_explicit(&r->write_idx, memory_order_relaxed);
	uint32_t rdx  = atomic_load_explicit(&r->read_idx, memory_order_acquire);
	uint32_t next = (w + 1) & (r->capacity - 1); /* capacity is power of two */

	if (next == rdx)
	{
		/* ring full */
		atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed);
		return 1;
	}

	r->slots[w] = handle;
	atomic_store_explicit(&r->write_idx, next, memory_order_release);
	return 0;
}

/**
 * @brief Pops a handle from the ring buffer.
 *
 * This function attempts to retrieve a handle from the ring buffer. It is a
 * non-blocking operation. If the buffer is empty, the operation fails and the
 * function returns a non-zero value. It uses relaxed and acquire/release
 * memory orders to ensure correct synchronization with the producer thread.
 *
 * @param r A pointer to the ring buffer instance.
 * @param out A pointer to a variable where the retrieved handle will be stored.
 * @return 0 on success, 1 if the buffer is empty.
 */
int
ring_pop(ring_t *r, uint32_t *out)
{
	uint32_t rdx = atomic_load_explicit(&r->read_idx, memory_order_relaxed);
	uint32_t w   = atomic_load_explicit(&r->write_idx, memory_order_acquire);

	if (rdx == w)
		return 1; /* empty */

	*out          = r->slots[rdx];
	uint32_t next = (rdx + 1) & (r->capacity - 1);
	atomic_store_explicit(&r->read_idx, next, memory_order_release);
	return 0;
}