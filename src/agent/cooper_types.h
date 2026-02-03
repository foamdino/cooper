/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COOPER_TYPES_H
#define COOPER_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <jvmti.h>

typedef struct package_filter package_filter_t;
typedef struct serialized_method_event serialized_method_event_t;
typedef struct serialized_class_event serialized_class_event_t;
typedef struct serialized_obj_alloc_event serialized_obj_alloc_event_t;
typedef enum method_event_type method_event_type_e;

enum method_event_type
{
	METHOD_ENTRY,
	METHOD_EXIT
};

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

struct serialized_method_event
{
	method_event_type_e type;
	jclass klass;
	uint64_t timestamp;
	uint64_t cpu;
	uint64_t thread_id;
	uint16_t class_name_len;
	uint16_t method_name_len;
	uint16_t method_sig_len;
	/* Variable length data follows: class_name, method_name, method_sig (all null
	 * terminated) */
	char data[];
};

struct serialized_class_event
{
	jclass klass; /* Global ref */
	uint16_t class_sig_len;
	/* Variable length data follows: class_sig (null terminated) */
	char data[];
};

struct serialized_obj_alloc_event
{
	int32_t
	    obj_alloc_index; /**< pre-resolved index into object_allocaton_metric soa */
	uint64_t sz;         /**< Object size in bytes */
};

#endif /* COOPER_TYPES_H */