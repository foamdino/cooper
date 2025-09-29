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
// TODO remove me
typedef struct pc_mapping pc_mapping_t;
typedef struct pc_chunk pc_chunk_t;
typedef struct bytecode_template bytecode_template_t;
typedef struct bytecode_builder bytecode_builder_t;
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

// TODO remove me
struct pc_mapping
{
	u4 original_pc;
	u4 new_pc;
};

struct pc_chunk
{
	u4 original_start;
	u4 original_end;
	u4 new_start;
	u4 new_len;
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

	pc_chunk_t chunks[32];
	u4 chunk_cnt;
};

// TODO have a single template as these are identical??
static const bytecode_template_t METHOD_ENTRY_TEMPLATE = {
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

static const bytecode_template_t METHOD_EXIT_TEMPLATE = {
    .name = "method_exit",
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

// TODO move to opcode.def X-Macro
static const u1 RETURN_OPCODES[] = {
    0xB1, /* return */
    0xAC, /* ireturn */
    0xAD, /* lreturn */
    0xAE, /* freturn */
    0xAF, /* dreturn */
    0xB0  /* areturn */
};

bytecode_result_e injection_add_method_tracking(arena_t *arena,
                                                class_file_t *cf,
                                                injection_config_t *config);

bytecode_result_e injection_add_method_tracking_clean(arena_t *arena,
                                                      class_file_t *cf,
                                                      injection_config_t *config);

/* Helper function to find or create constant pool entries */
u2 injection_find_or_add_utf8_constant(arena_t *arena, class_file_t *cf, const char *str);
u2 injection_find_or_add_class_constant(arena_t *arena,
                                        class_file_t *cf,
                                        const char *class_name);
u2 injection_find_or_add_methodref_constant(arena_t *arena,
                                            class_file_t *cf,
                                            const char *class_name,
                                            const char *method_name,
                                            const char *method_sig);

#endif /* JVM_INJECTION_H */