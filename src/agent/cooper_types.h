/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_TYPES_H
#define COOPER_TYPES_H

#include <stddef.h>
#include <jvmti.h>

typedef struct package_filter package_filter_t;
typedef struct class_q_entry class_q_entry_t;

/* Metric flags for method sampling */
enum metric_flags
{
	METRIC_FLAG_TIME   = (1 << 0), /* 1 */
	METRIC_FLAG_MEMORY = (1 << 1), /* 2 */
	METRIC_FLAG_CPU    = (1 << 2)  /* 4 */
};

/* Package filter configuration */
struct package_filter
{
	char **include_packages;
	size_t *package_lengths;
	size_t num_packages;
};

struct class_q_entry
{
	jclass klass;    /* Class reference to process */
	char *class_sig; /* Class signature (for logging) */
};

#endif /* COOPER_TYPES_H */