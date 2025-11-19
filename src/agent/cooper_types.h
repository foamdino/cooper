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
typedef struct class_q_entry class_q_entry_t;
typedef struct method_q_entry method_q_entry_t;

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

struct class_q_entry
{
	jclass klass;       /**< Class reference to process */
	char *class_sig;    /**< Class signature (for logging) */
	char **annotations; /**< Array of annotations */
};

struct method_q_entry
{
	method_event_type_e event_type; /**< Entry/Exit */
	char *class_name;
	char *method_name;
	char *method_sig;
	uint64_t timestamp;
	uint64_t cpu;
	uint64_t thread_id;
};

typedef struct
{
	method_event_type_e type;
	uint64_t timestamp;
	uint64_t cpu;
	uint64_t thread_id;
	uint16_t class_name_len;
	uint16_t method_name_len;
	uint16_t method_sig_len;
	/* Variable length data follows: class_name, method_name, method_sig (all null
	 * terminated) */
	char data[];
} serialized_method_event_t;

typedef struct
{
	jclass klass; /* Global ref */
	uint16_t class_sig_len;
	/* Variable length data follows: class_sig (null terminated) */
	char data[];
} serialized_class_event_t;

#endif /* COOPER_TYPES_H */