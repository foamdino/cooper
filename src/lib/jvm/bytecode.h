/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef JVM_BYTECODE_H
#define JVM_BYTECODE_H

#include "class.h"
#include "../arena.h"

/* X-Macro definition for constant pool entry types
 * Format: ENTRY(tag, read_logic, write_logic)
 */
#define CONSTANT_POOL_ENTRIES(ENTRY) \
	\
	/* UTF8 - variable length string with null termination */ \
	ENTRY(CONSTANT_Utf8, \
		{ \
			entry->info.utf8.length = read_u2_and_advance(data, offset); \
			entry->info.utf8.bytes = arena_alloc(arena, entry->info.utf8.length + 1); \
			if (!entry->info.utf8.bytes) \
				return BYTECODE_ERROR_MEMORY_ALLOCATION; \
			memcpy((void *)entry->info.utf8.bytes, \
			       &data[*offset], \
			       entry->info.utf8.length); \
			((u1 *)entry->info.utf8.bytes)[entry->info.utf8.length] = 0; \
			*offset += entry->info.utf8.length; \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.utf8.length); \
			memcpy(&buf[*offset], \
			       entry->info.utf8.bytes, \
			       entry->info.utf8.length); \
			*offset += entry->info.utf8.length; \
		}) \
	\
	/* String - reference to UTF8 constant */ \
	ENTRY(CONSTANT_String, \
		{ \
			entry->info.string = read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.string); \
		}) \
	\
	/* Class - reference to class name */ \
	ENTRY(CONSTANT_Class, \
		{ \
			entry->info.class_info.name_index = read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.class_info.name_index); \
		}) \
	\
	/* Method reference */ \
	ENTRY(CONSTANT_Methodref, \
		{ \
			entry->info.methodref.class_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.methodref.name_and_type_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.methodref.class_index); \
			write_u2_and_advance(buf, offset, entry->info.methodref.name_and_type_index); \
		}) \
	\
	/* Field reference */ \
	ENTRY(CONSTANT_Fieldref, \
		{ \
			entry->info.fieldref.class_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.fieldref.name_and_type_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.fieldref.class_index); \
			write_u2_and_advance(buf, offset, entry->info.fieldref.name_and_type_index); \
		}) \
	\
	/* Interface method reference */ \
	ENTRY(CONSTANT_InterfaceMethodref, \
		{ \
			entry->info.interfaceref.class_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.interfaceref.name_and_type_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.interfaceref.class_index); \
			write_u2_and_advance(buf, offset, entry->info.interfaceref.name_and_type_index); \
		}) \
	\
	/* Name and type descriptor */ \
	ENTRY(CONSTANT_NameAndType, \
		{ \
			entry->info.name_and_type.name_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.name_and_type.descriptor_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.name_and_type.name_index); \
			write_u2_and_advance(buf, offset, entry->info.name_and_type.descriptor_index); \
		}) \
	\
	/* Integer constant */ \
	ENTRY(CONSTANT_Integer, \
		{ \
			entry->info.integer = read_u4_and_advance(data, offset); \
		}, \
		{ \
			write_u4_and_advance(buf, offset, entry->info.integer); \
		}) \
	\
	/* Float constant */ \
	ENTRY(CONSTANT_Float, \
		{ \
			entry->info.float_info = read_u4_and_advance(data, offset); \
		}, \
		{ \
			write_u4_and_advance(buf, offset, entry->info.float_info); \
		}) \
	\
	/* Long constant - takes 2 constant pool slots */ \
	ENTRY(CONSTANT_Long, \
		{ \
			entry->info.long_info.high_bytes = \
			    read_u4_and_advance(data, offset); \
			entry->info.long_info.low_bytes = \
			    read_u4_and_advance(data, offset); \
		}, \
		{ \
			write_u4_and_advance(buf, offset, entry->info.long_info.high_bytes); \
			write_u4_and_advance(buf, offset, entry->info.long_info.low_bytes); \
		}) \
	\
	/* Double constant - takes 2 constant pool slots */ \
	ENTRY(CONSTANT_Double, \
		{ \
			entry->info.double_info.high_bytes = \
			    read_u4_and_advance(data, offset); \
			entry->info.double_info.low_bytes = \
			    read_u4_and_advance(data, offset); \
		}, \
		{ \
			write_u4_and_advance(buf, offset, entry->info.double_info.high_bytes); \
			write_u4_and_advance(buf, offset, entry->info.double_info.low_bytes); \
		}) \
	\
	/* Method handle */ \
	ENTRY(CONSTANT_MethodHandle, \
		{ \
			entry->info.methodhandle_info.reference_kind = \
			    read_u1_and_advance(data, offset); \
			entry->info.methodhandle_info.reference_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u1_and_advance(buf, offset, \
			    entry->info.methodhandle_info.reference_kind); \
			write_u2_and_advance(buf, offset, \
			    entry->info.methodhandle_info.reference_index); \
		}) \
	\
	/* Method type */ \
	ENTRY(CONSTANT_MethodType, \
		{ \
			entry->info.methodtype_info.descriptor_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, \
			    entry->info.methodtype_info.descriptor_index); \
		}) \
	\
	/* Dynamic constant */ \
	ENTRY(CONSTANT_Dynamic, \
		{ \
			entry->info.dynamic_info.bootstrap_method_attr_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.dynamic_info.name_and_type_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, \
			    entry->info.dynamic_info.bootstrap_method_attr_index); \
			write_u2_and_advance(buf, offset, \
			    entry->info.dynamic_info.name_and_type_index); \
		}) \
	\
	/* Invoke dynamic */ \
	ENTRY(CONSTANT_InvokeDynamic, \
		{ \
			entry->info.invokedynamic_info.bootstrap_method_attr_index = \
			    read_u2_and_advance(data, offset); \
			entry->info.invokedynamic_info.name_and_type_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, \
			    entry->info.invokedynamic_info.bootstrap_method_attr_index); \
			write_u2_and_advance(buf, offset, \
			    entry->info.invokedynamic_info.name_and_type_index); \
		}) \
	\
	/* Module reference */ \
	ENTRY(CONSTANT_Module, \
		{ \
			entry->info.module_info.name_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.module_info.name_index); \
		}) \
	\
	/* Package reference */ \
	ENTRY(CONSTANT_Package, \
		{ \
			entry->info.package_info.name_index = \
			    read_u2_and_advance(data, offset); \
		}, \
		{ \
			write_u2_and_advance(buf, offset, entry->info.package_info.name_index); \
		})

typedef enum bytecode_result bytecode_result_e;

enum bytecode_result
{
	BYTECODE_SUCCESS                     = 0,
	BYTECODE_ERROR_INVALID_MAGIC         = 1,
	BYTECODE_ERROR_UNSUPPORTED_VERSION   = 2,
	BYTECODE_ERROR_CORRUPT_CONSTANT_POOL = 3,
	BYTECODE_ERROR_CORRUPT_METHODS       = 4,
	BYTECODE_ERROR_MEMORY_ALLOCATION     = 5,
	BYTECODE_ERROR_INVALID_BYTECODE      = 6
};

bytecode_result_e bytecode_parse_class(arena_t *arena,
                                       const u1 *data,
                                       class_file_t **result);

bytecode_result_e bytecode_write_class(arena_t *arena,
                                       class_file_t *cf,
                                       u1 **data,
                                       u4 *len);

/* Utility functions */
const char *bytecode_get_class_name(const class_file_t *cf);
const char *bytecode_get_method_name(const class_file_t *cf, u2 method_index);

/* Helper for getting UTF8 strings from constant pool */
const char *bytecode_get_utf8_constant(const class_file_t *cf, u2 index);

#endif /* JVM_BYTECODE_H */