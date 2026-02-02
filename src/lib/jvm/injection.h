/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_INJECTION_H
#define JVM_INJECTION_H

#include "bytecode.h"
#include "opcode.h"
#include "../arena.h"

typedef struct injection_config injection_config_t;
typedef struct pc_map pc_map_t;
typedef struct bytecode_template bytecode_template_t;
typedef struct bytecode_builder bytecode_builder_t;
typedef struct constant_spec constant_spec_t;
struct injection_config
{
	const char *callback_class; /**< eg. "com/myagent/MethodTracker" */
	const char *entry_method;   /**< eg. "onMethodEntry" */
	const char *exit_method;    /**< eg. "onMethodExit" */
	const char
	    *entry_sig; /**< eg.
	                   "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V" */
	const char
	    *exit_sig; /**< eg.
	                  "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V" */
};

struct pc_map
{
	u4 original_start;
	u4 new_start;
};

struct bytecode_template
{
	const char *name;
	u4 len;
	const u1 bytes[16];        /* Fixed max size */
	u2 placeholder_offsets[4]; /* Where to substitute constant indices */
	u2 placeholder_cnt;
};

struct bytecode_builder
{
	arena_t *arena;
	u1 *buf;
	u4 capacity;
	u4 len;
	u4 chunk_cnt;
	u4 pc_map_capacity;
	pc_map_t *chunks;
};

static const bytecode_template_t METHOD_TEMPLATE = {
    .name = "method_entry",
    .len  = 12,
    .bytes =
	{
	    0x13,
	    0xFF,
	    0xFF, /* ldc_w #PLACEHOLDER0 (class name) */
	    0x13,
	    0xFF,
	    0xFF, /* ldc_w #PLACEHOLDER1 (method name) */
	    0x13,
	    0xFF,
	    0xFF, /* ldc_w #PLACEHOLDER2 (method signature) */
	    0xB8,
	    0xFF,
	    0xFF, /* invokestatic #PLACEHOLDER3 (entry callback) */
	    0x00,
	    0x00,
	    0x00,
	    0x00 /* padding */
	},
    .placeholder_offsets = {1, 4, 7, 10},
    .placeholder_cnt     = 4};

struct constant_spec
{
	u1 tag;
	union {
		/* For CONSTANT_Utf8 */
		struct
		{
			const char *str;
		} utf8;

		/* For CONSTANT_String */
		struct
		{
			u2 utf8_idx;
		} string;

		/* For CONSTANT_Class */
		struct
		{
			u2 name_idx;
		} class_info;

		/* For CONSTANT_NameAndType */
		struct
		{
			u2 name_idx;
			u2 descriptor_idx;
		} name_and_type;

		/* For CONSTANT_Methodref */
		struct
		{
			u2 class_idx;
			u2 name_and_type_idx;
		} methodref;
	} data;
};

bytecode_result_e injection_add_method_tracking(arena_t *arena,
                                                class_file_t *cf,
                                                injection_config_t *config);

/* Helper function to find or create constant pool entries */
bytecode_result_e injection_find_or_add_constant(arena_t *arena,
                                                 class_file_t *cf,
                                                 const constant_spec_t *spec,
                                                 u2 *out_index);

bytecode_result_e injection_find_or_add_utf8_constant(arena_t *arena,
                                                      class_file_t *cf,
                                                      const char *str,
                                                      u2 *out_index);

bytecode_result_e injection_find_or_add_string_constant(arena_t *arena,
                                                        class_file_t *cf,
                                                        const char *str,
                                                        u2 *out_index);

bytecode_result_e injection_find_or_add_class_constant(arena_t *arena,
                                                       class_file_t *cf,
                                                       const char *class_name,
                                                       u2 *out_index);

bytecode_result_e injection_find_or_add_methodref_constant(arena_t *arena,
                                                           class_file_t *cf,
                                                           const char *class_name,
                                                           const char *method_name,
                                                           const char *method_sig,
                                                           u2 *out_index);

#endif /* JVM_INJECTION_H */