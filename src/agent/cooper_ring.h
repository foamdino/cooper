/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_RING_H
#define COOPER_RING_H

#include "cooper.h"
#include "../lib/ring/ring.h"
#include "../lib/ring/ring_channel.h"

call_stack_sample_t *sample_alloc(ring_channel_t *ch, uint32_t *out_idx);

int sample_publish(ring_channel_t *ch, uint32_t idx);

call_stack_sample_t *sample_consume(ring_channel_t *ch, uint32_t *out_idx);

void sample_release(ring_channel_t *ch, uint32_t idx);

#endif /* COOPER_RING_H */