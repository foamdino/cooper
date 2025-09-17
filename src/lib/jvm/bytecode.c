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

// TODO not sure we need these

const char *
bytecode_get_method_name(const class_file_t *cf, u2 method_index)
{
	assert(cf != NULL);

	if (method_index >= cf->methods_count)
		return NULL;

	return bytecode_get_utf8_constant(cf, cf->methods[method_index].name_index);
}

// const char *
// bytecode_get_method_descriptor(const class_file_t *cf, u2 method_index)
// {
// 	return NULL;
// }

// const char *
// bytecode_get_field_name(const class_file_t *cf, u2 method_index)
// {
// 	return NULL;
// }

// const char *
// bytecode_get_field_descriptor(const class_file_t *cf, u2 method_index)
// {
// 	return NULL;
// }

static bytecode_result_e
parse_constant_pool_entry(arena_t *arena,
                          const u1 *data,
                          int *offset,
                          constant_pool_info_t *entry)
{

	entry->tag = data[(*offset)++];

	switch (entry->tag)
	{
		case CONSTANT_Utf8:
			entry->info.utf8.length = read_u2_and_advance(data, offset);
			entry->info.utf8.bytes =
			    arena_alloc(arena, entry->info.utf8.length + 1);
			if (!entry->info.utf8.bytes)
				return BYTECODE_ERROR_MEMORY_ALLOCATION;

			memcpy((void *)entry->info.utf8.bytes,
			       &data[*offset],
			       entry->info.utf8.length);
			/* Terminate string */
			((u1 *)entry->info.utf8.bytes)[entry->info.utf8.length] = 0;
			/* advance pointer */
			*offset += entry->info.utf8.length;
			break;

		/* Entry pointing to an instance of CONSTANT_Utf8 */
		case CONSTANT_String:
			entry->info.string = read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Class:
			entry->info.class_info.name_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Methodref:
			entry->info.methodref.class_index =
			    read_u2_and_advance(data, offset);
			entry->info.methodref.name_and_type_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_NameAndType:
			entry->info.name_and_type.name_index =
			    read_u2_and_advance(data, offset);
			entry->info.name_and_type.descriptor_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Integer:
			entry->info.integer = read_u4_and_advance(data, offset);
			break;

		case CONSTANT_Float:
			entry->info.flowt = read_u4_and_advance(data, offset);
			break;

		case CONSTANT_Fieldref:
			entry->info.fieldref.class_index =
			    read_u2_and_advance(data, offset);
			entry->info.fieldref.name_and_type_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_InterfaceMethodref:
			entry->info.interfaceref.class_index =
			    read_u2_and_advance(data, offset);
			entry->info.interfaceref.name_and_type_index =
			    read_u2_and_advance(data, offset);
			break;

		/* These take 2 constant pool slots */
		case CONSTANT_Long:
			entry->info.long_info.high_bytes =
			    read_u4_and_advance(data, offset);
			entry->info.long_info.low_bytes =
			    read_u4_and_advance(data, offset);
			break;

		case CONSTANT_Double:
			entry->info.double_info.high_bytes =
			    read_u4_and_advance(data, offset);
			entry->info.double_info.low_bytes =
			    read_u4_and_advance(data, offset);
			break;

		case CONSTANT_MethodHandle:
			entry->info.methodhandle_info.reference_kind =
			    read_u1_and_advance(data, offset);
			entry->info.methodhandle_info.reference_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_MethodType:
			entry->info.methodtype_info.descriptor_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Dynamic:
			entry->info.dynamic_info.bootstrap_method_attr_index =
			    read_u2_and_advance(data, offset);
			entry->info.dynamic_info.name_and_type_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_InvokeDynamic:
			entry->info.invokedynamic_info.bootstrap_method_attr_index =
			    read_u2_and_advance(data, offset);
			entry->info.invokedynamic_info.name_and_type_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Module:
			entry->info.module_info.name_index =
			    read_u2_and_advance(data, offset);
			break;

		case CONSTANT_Package:
			entry->info.module_info.name_index =
			    read_u2_and_advance(data, offset);
			break;

		default:
			printf("Warning: Unknown constant pool tag: %d\n", entry->tag);
			break; // return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
	}

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
parse_method(arena_t *arena, const u1 *data, int *offset, method_info_t *method)
{
	method->access_flags     = read_u2_and_advance(data, offset);
	method->name_index       = read_u2_and_advance(data, offset);
	method->descriptor_index = read_u2_and_advance(data, offset);
	method->attributes_count = read_u2_and_advance(data, offset);

	if (method->attributes_count > 0)
	{
		method->attributes =
		    arena_alloc(arena, method->attributes_count * sizeof(attr_info_t));
		if (!method->attributes)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < method->attributes_count; i++)
		{
			method->attributes[i].attribute_name_index =
			    read_u2_and_advance(data, offset);
			method->attributes[i].attribute_length =
			    read_u4_and_advance(data, offset);
			method->attributes[i].info = &data[*offset];
			/* advance pointer */
			*offset += method->attributes[i].attribute_length;
		}
	}
	else
		method->attributes = NULL;

	return BYTECODE_SUCCESS;
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

	cf->magic = read_u4_and_advance(data, &offset);
	if (cf->magic != CLASS_FILE_MAGIC)
		return BYTECODE_ERROR_INVALID_MAGIC;

	cf->major_version       = read_u2_and_advance(data, &offset);
	cf->minor_version       = read_u2_and_advance(data, &offset);
	cf->constant_pool_count = read_u2_and_advance(data, &offset);

	/* Constant pool must have at least 2 entries for a concrete class */
	if (cf->constant_pool_count < 2)
		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

	cf->constant_pool =
	    arena_alloc(arena, cf->constant_pool_count * sizeof(constant_pool_info_t));
	if (!cf->constant_pool)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* We set these if the _count is > 0 */
	cf->interfaces = NULL;
	cf->fields     = NULL;
	cf->methods    = NULL;

	/* Parse constant pool entries */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		bytecode_result_e rc = parse_constant_pool_entry(
		    arena, data, &offset, &cf->constant_pool[i]);
		if (rc != BYTECODE_SUCCESS)
			return rc;

		/* Long and Double are two slots */
		if (cf->constant_pool[i].tag == CONSTANT_Long
		    || cf->constant_pool[i].tag == CONSTANT_Double)
		{
			i++; /* advance pointer */

			/* Mark this slot as unusable
			required by jvm spec:
			The constant_pool index n+1 must be valid but is considered
			unusable.*/
			if (i < cf->constant_pool_count)
				cf->constant_pool[i].tag = 0;
		}
	}

	/* Parse the class info */
	cf->access_flags = read_u2_and_advance(data, &offset);
	cf->this_class   = read_u2_and_advance(data, &offset);
	cf->super_class  = read_u2_and_advance(data, &offset);

	/* Parse interfaces */
	cf->interfaces_count = read_u2_and_advance(data, &offset);
	if (cf->interfaces_count > 0)
	{
		cf->interfaces = arena_alloc(arena, cf->interfaces_count * sizeof(u2));
		if (!cf->interfaces)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < cf->interfaces_count; i++)
			cf->interfaces[i] = read_u2_and_advance(data, &offset);
	}

	/* Parse fields */
	cf->fields_count = read_u2_and_advance(data, &offset);
	if (cf->fields_count > 0)
	{
		cf->fields = arena_alloc(arena, cf->fields_count * sizeof(field_info_t));
		if (!cf->fields)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < cf->fields_count; i++)
		{
			// TODO refactor into parse_field(arena, data, &offset,
			// &cf->fields[i]);
			cf->fields[i].access_flags = read_u2_and_advance(data, &offset);
			cf->fields[i].name_index   = read_u2_and_advance(data, &offset);
			cf->fields[i].descriptor_index =
			    read_u2_and_advance(data, &offset);
			cf->fields[i].attributes_count =
			    read_u2_and_advance(data, &offset);

			/* TODO complete this */
			for (u2 j = 0; j < cf->fields[i].attributes_count; j++)
			{
				/* attribute_name_index */
				read_u2_and_advance(
				    data, &offset); // TODO don't just discard this
				u4 attr_len = read_u4_and_advance(data, &offset);
				/* advance the pointer */
				offset += attr_len;
			}
		}
	}

	/* Parse methods */
	cf->methods_count = read_u2_and_advance(data, &offset);
	if (cf->methods_count > 0)
	{
		cf->methods =
		    arena_alloc(arena, cf->methods_count * sizeof(method_info_t));
		if (!cf->methods)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < cf->methods_count; i++)
		{
			bytecode_result_e rc =
			    parse_method(arena, data, &offset, &cf->methods[i]);
			if (rc != BYTECODE_SUCCESS)
				return rc;
		}
	}

	/* Parse attributes */
	*result = cf;
	return BYTECODE_SUCCESS;
}

void
bytecode_print_class_info(const class_file_t *cf)
{
	printf("Class File Information:\n");
	printf("  Magic: 0x%08X\n", cf->magic);
	printf("  Version: %d.%d\n", cf->major_version, cf->minor_version);
	printf("  Class: %s\n", bytecode_get_class_name(cf));
	printf("  Constant Pool: %d entries\n", cf->constant_pool_count - 1);
	printf("  Methods: %d\n", cf->methods_count);
	printf("  Fields: %d\n", cf->fields_count);

	printf("\nMethods:\n");
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *name =
		    bytecode_get_utf8_constant(cf, cf->methods[i].name_index);
		const char *desc =
		    bytecode_get_utf8_constant(cf, cf->methods[i].descriptor_index);
		printf("[%d] %s %s\n", i, name ? name : "?", desc ? desc : "?");
	}
}