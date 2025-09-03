/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RING_CHANNEL_H
#define RING_CHANNEL_H

#include "ring_store.h"
#include "ring.h"

typedef struct ring_channel ring_channel_t;

struct ring_channel
{
	ring_store_t store; /**< backing array */
	ring_t free_ring;   /**< indices available for producer */
	ring_t ready_ring;  /**< indices filled for consumer */
};

#endif /* RING_CHANNEL_H */