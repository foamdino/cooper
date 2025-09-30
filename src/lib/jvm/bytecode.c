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
	assert(cf != NULL);

	if (method_index >= cf->methods_count)
		return NULL;

	return bytecode_get_utf8_constant(cf, cf->methods[method_index].name_index);
}

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
			entry->info.float_info = read_u4_and_advance(data, offset);
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
			entry->info.package_info.name_index =
			    read_u2_and_advance(data, offset);
			break;

		default:
			printf("Warning: Unknown constant pool tag: %d\n", entry->tag);
			break; // return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
	}

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
parse_attribute(const u1 *data, int *offset, attr_info_t *attr)
{
	attr->attribute_name_index = read_u2_and_advance(data, offset);
	attr->attribute_length     = read_u4_and_advance(data, offset);
	attr->info                 = &data[*offset];
	*offset += attr->attribute_length;

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
parse_method(arena_t *arena, const u1 *data, int *offset, method_info_t *method)
{
	method->access_flags     = read_u2_and_advance(data, offset);
	method->name_index       = read_u2_and_advance(data, offset);
	method->descriptor_index = read_u2_and_advance(data, offset);
	method->attributes_count = read_u2_and_advance(data, offset);
	method->attributes       = NULL;

	if (method->attributes_count > 0)
	{
		method->attributes =
		    arena_alloc(arena, method->attributes_count * sizeof(attr_info_t));
		if (!method->attributes)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < method->attributes_count; i++)
		{
			bytecode_result_e rc =
			    parse_attribute(data, offset, &method->attributes[i]);
			if (rc != BYTECODE_SUCCESS)
				return rc;
		}
	}

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
parse_field(arena_t *arena, const u1 *data, int *offset, field_info_t *field)
{
	field->access_flags     = read_u2_and_advance(data, offset);
	field->name_index       = read_u2_and_advance(data, offset);
	field->descriptor_index = read_u2_and_advance(data, offset);
	field->attributes_count = read_u2_and_advance(data, offset);

	field->attributes = NULL;

	if (field->attributes_count > 0)
	{
		field->attributes =
		    arena_alloc(arena, field->attributes_count * sizeof(attr_info_t));
		if (!field->attributes)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < field->attributes_count; i++)
		{
			bytecode_result_e rc =
			    parse_attribute(data, offset, &field->attributes[i]);
			if (rc != BYTECODE_SUCCESS)
				return rc;
		}
	}

	return BYTECODE_SUCCESS;
}

/* Class file representation
https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.4
ClassFile {
    u4             magic;
    u2             minor_version;
    u2             major_version;
    u2             constant_pool_count;
    cp_info        constant_pool[constant_pool_count-1];
    u2             access_flags;
    u2             this_class;
    u2             super_class;
    u2             interfaces_count;
    u2             interfaces[interfaces_count];
    u2             fields_count;
    field_info     fields[fields_count];
    u2             methods_count;
    method_info    methods[methods_count];
    u2             attributes_count;
    attribute_info attributes[attributes_count];
} */
// TODO use len at some point?
//  perhaps decrement len by bytes advanced and ensure that the result is 0 at end
//  perhaps pass len to read_x_and_advance and check in these functions?
bytecode_result_e
bytecode_parse_class(arena_t *arena, const u1 *data, class_file_t **result)
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

	cf->minor_version       = read_u2_and_advance(data, &offset);
	cf->major_version       = read_u2_and_advance(data, &offset);
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
	cf->attributes = NULL;

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
			bytecode_result_e rc =
			    parse_field(arena, data, &offset, &cf->fields[i]);
			if (rc != BYTECODE_SUCCESS)
				return rc;
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
	cf->attributes_count = read_u2_and_advance(data, &offset);
	if (cf->attributes_count > 0)
	{
		cf->attributes =
		    arena_alloc(arena, cf->attributes_count * sizeof(attr_info_t));
		if (!cf->attributes)
			return BYTECODE_ERROR_MEMORY_ALLOCATION;

		for (u2 i = 0; i < cf->attributes_count; i++)
		{
			bytecode_result_e rc =
			    parse_attribute(data, &offset, &cf->attributes[i]);
			if (rc != BYTECODE_SUCCESS)
				return rc;
		}
	}

	*result = cf;
	return BYTECODE_SUCCESS;
}

static bytecode_result_e
write_constant_pool_entry(u1 *buf, int *offset, const constant_pool_info_t *entry)

{
	/* Write the tag */
	buf[(*offset)++] = entry->tag;

	/* What do we have to write ...*/
	switch (entry->tag)
	{
		case CONSTANT_Utf8:
			write_u2_and_advance(buf, offset, entry->info.utf8.length);
			memcpy(&buf[*offset],
			       entry->info.utf8.bytes,
			       entry->info.utf8.length);
			*offset += entry->info.utf8.length;
			break;

		/* Entry pointing to an instance of CONSTANT_Utf8 */
		case CONSTANT_String:
			write_u2_and_advance(buf, offset, entry->info.string);
			break;

		case CONSTANT_Class:
			write_u2_and_advance(
			    buf, offset, entry->info.class_info.name_index);
			break;

		case CONSTANT_Methodref:
			write_u2_and_advance(
			    buf, offset, entry->info.methodref.class_index);
			write_u2_and_advance(
			    buf, offset, entry->info.methodref.name_and_type_index);
			break;

		case CONSTANT_NameAndType:
			write_u2_and_advance(
			    buf, offset, entry->info.name_and_type.name_index);
			write_u2_and_advance(
			    buf, offset, entry->info.name_and_type.descriptor_index);
			break;

		case CONSTANT_Integer:
			write_u4_and_advance(buf, offset, entry->info.integer);
			break;

		case CONSTANT_Float:
			write_u4_and_advance(buf, offset, entry->info.float_info);
			break;

		case CONSTANT_Fieldref:
			write_u2_and_advance(
			    buf, offset, entry->info.fieldref.class_index);
			write_u2_and_advance(
			    buf, offset, entry->info.fieldref.name_and_type_index);
			break;

		case CONSTANT_InterfaceMethodref:
			write_u2_and_advance(
			    buf, offset, entry->info.interfaceref.class_index);
			write_u2_and_advance(
			    buf, offset, entry->info.interfaceref.name_and_type_index);
			break;

		/* These take 2 constant pool slots */
		case CONSTANT_Long:
			write_u4_and_advance(
			    buf, offset, entry->info.long_info.high_bytes);
			write_u4_and_advance(
			    buf, offset, entry->info.long_info.low_bytes);
			break;

		case CONSTANT_Double:
			write_u4_and_advance(
			    buf, offset, entry->info.double_info.high_bytes);
			write_u4_and_advance(
			    buf, offset, entry->info.double_info.low_bytes);
			break;

		case CONSTANT_MethodHandle:
			write_u1_and_advance(
			    buf, offset, entry->info.methodhandle_info.reference_kind);
			write_u2_and_advance(
			    buf, offset, entry->info.methodhandle_info.reference_index);
			break;

		case CONSTANT_MethodType:
			write_u2_and_advance(
			    buf, offset, entry->info.methodtype_info.descriptor_index);
			break;

		case CONSTANT_Dynamic:
			write_u2_and_advance(
			    buf,
			    offset,
			    entry->info.dynamic_info.bootstrap_method_attr_index);
			write_u2_and_advance(
			    buf, offset, entry->info.dynamic_info.name_and_type_index);
			break;

		case CONSTANT_InvokeDynamic:
			write_u2_and_advance(
			    buf,
			    offset,
			    entry->info.invokedynamic_info.bootstrap_method_attr_index);
			write_u2_and_advance(
			    buf,
			    offset,
			    entry->info.invokedynamic_info.name_and_type_index);
			break;

		case CONSTANT_Module:
			write_u2_and_advance(
			    buf, offset, entry->info.module_info.name_index);
			break;

		case CONSTANT_Package:
			write_u2_and_advance(
			    buf, offset, entry->info.package_info.name_index);
			break;

		default:
			return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
	}

	return BYTECODE_SUCCESS;
}

bytecode_result_e
bytecode_write_class(arena_t *arena, class_file_t *cf, u1 **data, u4 *len)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(data != NULL);
	assert(len != NULL);

	if (!arena || !cf || !data || !len)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Calc ~size needed */
	u4 est_sz = 1024;
	est_sz += cf->constant_pool_count * 64;
	est_sz += cf->methods_count * 512;

	u1 *buf = arena_alloc(arena, est_sz);
	if (!buf)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset = 0;

	/* Write header */
	write_u4_and_advance(buf, &offset, cf->magic);
	write_u2_and_advance(buf, &offset, cf->minor_version);
	write_u2_and_advance(buf, &offset, cf->major_version);

	/* Constant pool */
	write_u2_and_advance(buf, &offset, cf->constant_pool_count);

	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		const constant_pool_info_t *entry = &cf->constant_pool[i];
		if (entry->tag == 0)
			continue;

		bytecode_result_e res = write_constant_pool_entry(buf, &offset, entry);

		/* Should only happen if we are writing incorrect data */
		if (res != BYTECODE_SUCCESS)
			return res;

		/* These take up two slots, to need to advance again */
		if (entry->tag == CONSTANT_Long || entry->tag == CONSTANT_Double)
			i++;
	}

	/* Write class information */
	write_u2_and_advance(buf, &offset, cf->access_flags);
	write_u2_and_advance(buf, &offset, cf->this_class);
	write_u2_and_advance(buf, &offset, cf->super_class);

	/* Write interfaces */
	write_u2_and_advance(buf, &offset, cf->interfaces_count);
	for (u2 i = 0; i < cf->interfaces_count; i++)
	{
		write_u2_and_advance(buf, &offset, cf->interfaces[i]);
	}

	/* Write fields */
	write_u2_and_advance(buf, &offset, cf->fields_count);
	for (u2 i = 0; i < cf->fields_count; i++)
	{
		const field_info_t *field = &cf->fields[i];
		write_u2_and_advance(buf, &offset, field->access_flags);
		write_u2_and_advance(buf, &offset, field->name_index);
		write_u2_and_advance(buf, &offset, field->descriptor_index);

		/* Write field attributes */
		write_u2_and_advance(buf, &offset, field->attributes_count);
		for (u2 j = 0; j < field->attributes_count; j++)
		{
			write_u2_and_advance(
			    buf, &offset, field->attributes[j].attribute_name_index);
			write_u4_and_advance(
			    buf, &offset, field->attributes[j].attribute_length);
			memcpy(&buf[offset],
			       field->attributes[j].info,
			       field->attributes[j].attribute_length);
			offset += field->attributes[j].attribute_length;
		}
	}

	/* Write methods */
	write_u2_and_advance(buf, &offset, cf->methods_count);
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const method_info_t *method = &cf->methods[i];
		write_u2_and_advance(buf, &offset, method->access_flags);
		write_u2_and_advance(buf, &offset, method->name_index);
		write_u2_and_advance(buf, &offset, method->descriptor_index);

		/* Write method attributes */
		write_u2_and_advance(buf, &offset, method->attributes_count);
		for (u2 j = 0; j < method->attributes_count; j++)
		{
			write_u2_and_advance(
			    buf, &offset, method->attributes[j].attribute_name_index);
			write_u4_and_advance(
			    buf, &offset, method->attributes[j].attribute_length);
			memcpy(&buf[offset],
			       method->attributes[j].info,
			       method->attributes[j].attribute_length);
			offset += method->attributes[j].attribute_length;
		}
	}

	/* Write class attributes */
	write_u2_and_advance(buf, &offset, cf->attributes_count);
	for (u2 i = 0; i < cf->attributes_count; i++)
	{
		write_u2_and_advance(
		    buf, &offset, cf->attributes[i].attribute_name_index);
		write_u4_and_advance(buf, &offset, cf->attributes[i].attribute_length);
		memcpy(&buf[offset],
		       cf->attributes[i].info,
		       cf->attributes[i].attribute_length);
		offset += cf->attributes[i].attribute_length;
	}

	/* Return results */
	*data = buf;
	*len  = offset;

	return BYTECODE_SUCCESS;
}
