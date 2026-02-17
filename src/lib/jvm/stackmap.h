/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STACKMAP_H
#define STACKMAP_H

#include "class.h"
#include "../arena.h"

#define DESCRIPTOR_MAX_PARAMS 255

typedef enum verification_type verification_type_e;
typedef struct verification_type_entry verification_type_entry_t;
typedef struct frame_state frame_state_t;
typedef struct frame_cpu frame_cpu_t;
typedef struct method_descriptor method_descriptor_t;

/* Verification types from JVMS §4.10.1.2 */
enum verification_type
{
	ITEM_Top               = 0,
	ITEM_Integer           = 1,
	ITEM_Float             = 2,
	ITEM_Double            = 3, /* Takes 2 slots */
	ITEM_Long              = 4, /* Takes 2 slots */
	ITEM_Null              = 5,
	ITEM_UninitializedThis = 6,
	ITEM_Object            = 7,
	ITEM_Uninitialized     = 8 /* Has offset */
};

struct verification_type_entry
{
	verification_type_e type;
	u2 cpool_idx; /* For ITEM_Object */
	u2 offset;    /* For ITEM_Unintialized */
};

struct frame_state
{
	u4 pc;
	u2 locals_cnt;
	verification_type_entry_t locals[256];
	u2 stack_cnt;
	verification_type_entry_t stack[256];
};

/* Frame cpu - tracks state during simulation */
struct frame_cpu
{
	arena_t *arena;
	const class_file_t *cf;
	frame_state_t current_frame;

	/* Branch targets requiring frames */
	u4 *target_pcs;
	u4 target_cnt;
	u4 target_capacity;

	/* Computed frames at target */
	frame_state_t *frames;
	u4 frame_cnt;
	u4 frame_capacity;

	/* Exception handlers */
	u4 *handler_pcs;
	u4 handler_cnt;
};

/* Result of parsing a method descriptor */
struct method_descriptor
{
	verification_type_entry_t params[DESCRIPTOR_MAX_PARAMS];
	u2 params_cnt; /* Number of slots (long/double = 2) */
	verification_type_entry_t return_type;
	int is_void;
};

/* Public API */
frame_cpu_t *fc_create(arena_t *arena, const class_file_t *cf);
int fc_compute_frames(frame_cpu_t *fc,
                      const u1 *bytecode,
                      u4 bytecode_len,
                      const code_info_t *code_info);
int fc_encode_stackmap_table(frame_cpu_t *fc, u1 *output, u4 *output_len);

/* Parsing functions */

/*
 * Parse a method descriptor string e.g. "(Ljava/lang/String;I)V"
 *
 * Walks the descriptor, resolving:
 *   L...; -> ITEM_Object with the class's cpool index
 *   [     -> ITEM_Object (arrays are objects)
 *   I,B,C,S,Z -> ITEM_Integer
 *   J     -> ITEM_Long  (takes 2 slots, second is ITEM_Top)
 *   F     -> ITEM_Float
 *   D     -> ITEM_Double (takes 2 slots, second is ITEM_Top)
 *   V     -> void (return only)
 *
 * Returns 0 on success, -1 on parse error.
 */
int parse_method_descriptor(const class_file_t *cf,
                            const char *descriptor,
                            method_descriptor_t *result);

/*
 * Parse a field descriptor string e.g. "Ljava/lang/String;" or "I" or "[B"
 *
 * Returns 0 on success, -1 on parse error.
 */
int parse_field_descriptor(const class_file_t *cf,
                           const char *descriptor,
                           verification_type_entry_t *result);

/*
 * Given a Methodref/InterfaceMethodref constant pool index, chase:
 *   Methodref -> name_and_type_index -> descriptor_index -> UTF-8 string
 *
 * Returns the descriptor string or NULL on error.
 */
const char *get_methodref_descriptor(const class_file_t *cf, u2 methodref_index);

/*
 * Given a Fieldref constant pool index, chase:
 *   Fieldref -> name_and_type_index -> descriptor_index -> UTF-8 string
 *
 * Returns the descriptor string or NULL on error.
 */
const char *get_fieldref_descriptor(const class_file_t *cf, u2 fieldref_index);

/*
 * Given a Methodref/Fieldref/InterfaceMethodref constant pool index, resolve
 * the class_index to a CONSTANT_Class cpool index (for ITEM_Object).
 *
 * Returns the class cpool index, or 0 on error.
 */
u2 get_ref_class_index(const class_file_t *cf, u2 ref_index);

#endif /* STACKMAP_H */