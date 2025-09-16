/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bytecode.h"

/* Helper for getting UTF8 strings from constant pool */
const char *
bytecode_get_utf8_constant(const class_file_t *cf, u2 idx)
{
	assert(cf != NULL);

	if (idx == 0 || idx >= cf->constant_pool_count)
		return NULL;

	if (cf->constant_pool[idx].tag != CONSTANT_Utf8)
		return NULL;

	return (const char *)cf->constant_pool[idx].info.utf8.bytes;
}

const char *
bytecode_get_class_name(const class_file_t *cf)
{
	assert(cf != NULL);

	if (cf->this_class >= cf->constant_pool_count)
		return NULL;

	if (cf->constant_pool[cf->this_class].tag != CONSTANT_Class)
		return NULL;

	u2 name_idx = cf->constant_pool[cf->this_class].info.class_info.name_index;
	return bytecode_get_utf8_constant(cf, name_idx);
}

const char *
bytecode_get_method_name(const class_file_t *cf, u2 method_index)
{
	return NULL;
}

const char *
bytecode_get_method_descriptor(const class_file_t *cf, u2 method_index)
{
	return NULL;
}

bytecode_result_e
bytecode_parse_class(arena_t *arena, const u1 *data, u4 len, class_file_t **result)
{
	if (!arena || !data || !result)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	class_file_t *cf = arena_alloc(arena, sizeof(class_file_t));
	if (!cf)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset = 0;

	cf->magic = read_u4(data, &offset);
	if (cf->magic != CLASS_FILE_MAGIC)
		return BYTECODE_ERROR_INVALID_MAGIC;

	// TODO complete me

	*result = cf;
	return BYTECODE_SUCCESS;
}

void
bytecode_print_class_info(const class_file_t *cf)
{
	printf("Class File Information:\n");
	printf("  Magic: 0x%08X\n", cf->magic);
	// TODO need to complete class file parsing
	// printf("  Version: %d.%d\n", cf->major_version, cf->minor_version);
	// printf("  Class: %s\n", bytecode_get_class_name(cf));
	// printf("  Constant Pool: %d entries\n", cf->constant_pool_count - 1);
	// printf("  Methods: %d\n", cf->methods_count);
	// printf("  Fields: %d\n", cf->fields_count);

	// printf("\nMethods:\n");
	// for (u2 i = 0; i < cf->methods_count; i++) {
	//     const char* name = bytecode_get_utf8_constant(cf,
	//     cf->methods[i].name_index); const char* desc =
	//     bytecode_get_utf8_constant(cf, cf->methods[i].descriptor_index); printf("
	//     [%d] %s %s\n", i, name ? name : "?", desc ? desc : "?");
	// }
}