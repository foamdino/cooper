/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_BYTECODE_H
#define JVM_BYTECODE_H

#include "class.h"
#include "../arena.h"

typedef enum bytecode_result bytecode_result_e;

enum bytecode_result
{
	BYTECODE_SUCCESS                     = 0,
	BYTECODE_ERROR_INVALID_MAGIC         = -1,
	BYTECODE_ERROR_UNSUPPORTED_VERSION   = -2,
	BYTECODE_ERROR_CORRUPT_CONSTANT_POOL = -3,
	BYTECODE_ERROR_CORRUPT_METHODS       = -4,
	BYTECODE_ERROR_MEMORY_ALLOCATION     = -5,
	BYTECODE_ERROR_INVALID_BYTECODE      = -6
};

bytecode_result_e bytecode_parse_class(arena_t *arena,
                                       const u1 *data,
                                       u4 len,
                                       class_file_t **result);

bytecode_result_e bytecode_write_class(arena_t *arena,
                                       class_file_t *cf,
                                       u1 **data,
                                       u4 *len);

/* Utility functions */
const char *bytecode_get_class_name(const class_file_t *cf);
const char *bytecode_get_method_name(const class_file_t *cf, u2 method_index);
const char *bytecode_get_method_descriptor(const class_file_t *cf, u2 method_index);
void bytecode_print_class_info(const class_file_t *cf);
void bytecode_print_method_details(const class_file_t *cf, u2 method_idx);

/* Helper for getting UTF8 strings from constant pool */
const char *bytecode_get_utf8_constant(const class_file_t *cf, u2 index);

#endif /* JVM_BYTECODE_H */