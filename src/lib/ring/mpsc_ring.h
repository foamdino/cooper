/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MPSC_RING_H
#define MPSC_RING_H

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ring_store.h"

/* Return codes */
#define MPSC_OK    0
#define MPSC_FULL  1
#define MPSC_EMPTY 2
#define MPSC_BUSY  3 /* Slot reserved but not yet committed */

typedef struct mpsc_ring mpsc_ring_t;

/**
 * MPSC Ring Buffer
 *
 * A Multi-Producer Single-Consumer lock-free ring buffer.
 * Uses a flags array to synchronize access to slots, preventing the
 * "read-before-write" race condition common in simple atomic counter implementations.
 */
struct mpsc_ring
{
	ring_store_t store;           /**< Storage for data and flags */
	atomic_uint_fast64_t head;    /**< Producer write index */
	atomic_uint_fast64_t tail;    /**< Consumer read index */
	atomic_uint_fast64_t dropped; /**< Count of dropped items */
};

/**
 * Initialize the MPSC ring buffer
 *
 * @param ring      Pointer to ring structure
 * @param capacity  Number of slots (must be power of 2)
 * @param elem_sz   Size of each slot in bytes
 * @return          0 on success, non-zero on failure
 */
int mpsc_ring_init(mpsc_ring_t *ring, uint32_t capacity, uint32_t elem_sz);

/**
 * Free the MPSC ring buffer resources
 */
void mpsc_ring_free(mpsc_ring_t *ring);

/**
 * Reserve a slot for writing (Producer)
 *
 * @param ring        Pointer to ring
 * @param out_handle  Output pointer to the reserved handle (index)
 * @return            MPSC_OK on success, MPSC_FULL if ring is full
 */
int mpsc_ring_reserve(mpsc_ring_t *ring, uint32_t *out_handle);

/**
 * Commit a previously reserved slot (Producer)
 *
 * @param ring    Pointer to ring
 * @param handle  Handle returned by mpsc_ring_reserve
 */
void mpsc_ring_commit(mpsc_ring_t *ring, uint32_t handle);

/**
 * Consume a slot (Consumer)
 *
 * @param ring        Pointer to ring
 * @param out_handle  Output pointer to the ready handle
 * @return            MPSC_OK on success
 *                    MPSC_EMPTY if no data available
 *                    MPSC_BUSY if producer reserved slot but hasn't committed yet
 */
int mpsc_ring_consume(mpsc_ring_t *ring, uint32_t *out_handle);

/**
 * Release a consumed slot (Consumer)
 *
 * @param ring    Pointer to ring
 * @param handle  Handle being released
 */
void mpsc_ring_release(mpsc_ring_t *ring, uint32_t handle);

/**
 * Get a pointer to the data at the given handle
 *
 * @param ring    Pointer to ring
 * @param handle  Handle to look up
 * @return        Pointer to data
 */
void *mpsc_ring_get(mpsc_ring_t *ring, uint32_t handle);

#endif /* MPSC_RING_H */
