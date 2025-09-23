/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <stdio.h>
#include "injection.h"

// TODO smush these into a single helper
// with a switch for tag, similar to the constant pool parsing
u2
injection_find_or_add_utf8_constant(arena_t *arena, class_file_t *cf, const char *str)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(str != NULL);

	/* Check if constant is present */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Utf8)
		{
			const char *existing =
			    (const char *)cf->constant_pool[i].info.utf8.bytes;
			if (existing && strcmp(existing, str) == 0)
				return i;
		}
	}

	/* Not present, need to add */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));

	// TODO fix this, we should use a param for output and a normal result code
	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Utf8 */
	u2 new_idx                         = cf->constant_pool_count;
	new_pool[new_idx].tag              = CONSTANT_Utf8;
	new_pool[new_idx].info.utf8.length = strlen(str);
	new_pool[new_idx].info.utf8.bytes  = arena_alloc(arena, strlen(str) + 1);
	if (!new_pool[new_idx].info.utf8.bytes)
		return 0; // TODO see other comment

	/* Copy the bytes */
	strcpy((char *)new_pool[new_idx].info.utf8.bytes, str);

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

u2
injection_find_or_add_string_constant(arena_t *arena, class_file_t *cf, const char *str)
{
	/* First, get or create the UTF8 constant */
	u2 utf8_index = injection_find_or_add_utf8_constant(arena, cf, str);
	if (utf8_index == 0)
		return 0;

	/* Check if String constant already exists */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_String)
		{
			if (cf->constant_pool[i].info.string == utf8_index)
				return i;
		}
	}

	/* Create new String constant */
	u2 new_size = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_size * sizeof(constant_pool_info_t));
	if (!new_pool)
		return 0;

	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	u2 new_index                    = cf->constant_pool_count;
	new_pool[new_index].tag         = CONSTANT_String;
	new_pool[new_index].info.string = utf8_index;

	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_size;

	return new_index;
}

u2
injection_find_or_add_class_constant(arena_t *arena,
                                     class_file_t *cf,
                                     const char *class_name)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(class_name != NULL);

	u2 name_idx = injection_find_or_add_utf8_constant(arena, cf, class_name);
	if (name_idx == 0)
		return 0;

	/* Check if this class constant exists */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Class)
		{
			if (cf->constant_pool[i].info.class_info.name_index == name_idx)
				return i;
		}
	}

	/* Not present, need to add */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));

	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Class*/
	u2 new_idx                                   = cf->constant_pool_count;
	new_pool[new_idx].tag                        = CONSTANT_Class;
	new_pool[new_idx].info.class_info.name_index = name_idx;

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

u2
injection_find_or_add_methodref_constant(arena_t *arena,
                                         class_file_t *cf,
                                         const char *class_name,
                                         const char *method_name,
                                         const char *method_sig)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(class_name != NULL);
	assert(method_name != NULL);
	assert(method_sig != NULL);

	/* Get the class constant */
	u2 class_idx = injection_find_or_add_class_constant(arena, cf, class_name);
	if (class_idx == 0)
		return 0;

	/* Get name and type constants */
	u2 name_idx = injection_find_or_add_utf8_constant(arena, cf, method_name);
	if (name_idx == 0)
		return 0;

	u2 desc_idx = injection_find_or_add_utf8_constant(arena, cf, method_sig);
	if (desc_idx == 0)
		return 0;

	/* Find or create the NameAndType constant */
	u2 name_type_idx = 0;
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_NameAndType)
		{
			if (cf->constant_pool[i].info.name_and_type.name_index == name_idx
			    && cf->constant_pool[i].info.name_and_type.descriptor_index
			           == desc_idx)
			{
				name_type_idx = i;
				break;
			}
		}
	}

	/* Create a new NameAndType constant as we couldn't find it */
	if (name_type_idx == 0)
	{
		u2 new_count = cf->constant_pool_count + 1;
		constant_pool_info_t *new_pool =
		    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));
		if (!new_pool)
			return 0;

		/* Copy the existing entries over */
		memcpy(new_pool,
		       cf->constant_pool,
		       cf->constant_pool_count * sizeof(constant_pool_info_t));

		name_type_idx               = cf->constant_pool_count;
		new_pool[name_type_idx].tag = CONSTANT_NameAndType;
		new_pool[name_type_idx].info.name_and_type.name_index       = name_idx;
		new_pool[name_type_idx].info.name_and_type.descriptor_index = desc_idx;

		cf->constant_pool       = new_pool;
		cf->constant_pool_count = new_count;
	}

	/* Check for methdoref */
	for (u2 i = 1; i < cf->constant_pool_count; i++)
	{
		if (cf->constant_pool[i].tag == CONSTANT_Methodref)
		{
			if (cf->constant_pool[i].info.methodref.class_index == class_idx
			    && cf->constant_pool[i].info.methodref.name_and_type_index
			           == name_type_idx)
				return i;
		}
	}

	/* Need to create methodref */
	u2 new_count = cf->constant_pool_count + 1;
	constant_pool_info_t *new_pool =
	    arena_alloc(arena, new_count * sizeof(constant_pool_info_t));
	if (!new_pool)
		return 0;

	/* Copy the existing entries over */
	memcpy(new_pool,
	       cf->constant_pool,
	       cf->constant_pool_count * sizeof(constant_pool_info_t));

	/* Add new CONSTANT_Methodref */
	u2 new_idx                                           = cf->constant_pool_count;
	new_pool[new_idx].tag                                = CONSTANT_Methodref;
	new_pool[new_idx].info.methodref.class_index         = class_idx;
	new_pool[new_idx].info.methodref.name_and_type_index = name_type_idx;

	/* Update the class file constant pool */
	cf->constant_pool       = new_pool;
	cf->constant_pool_count = new_count;

	return new_idx;
}

// static u4
// find_new_pc(pc_mapping_t *map, u4 count, u4 original_pc)
// {
// 	for (u4 i = 0; i < count; i++)
// 	{
// 		if (map[i].original_pc == original_pc)
// 			return map[i].new_pc;

// 		/* Return the closest preceding mapping */
// 		if (map[i].original_pc > original_pc)
// 		{
// 			return i > 0 ? map[i - 1].new_pc
// 			                   + (original_pc - map[i - 1].original_pc)
// 			             : original_pc;
// 		}
// 	}
// 	/* Fallback - should not reach here if map is complete */
// 	return original_pc;
// }

bytecode_builder_t *
bb_create(arena_t *arena, u4 initial_capacity)
{
	bytecode_builder_t *bb = arena_alloc(arena, sizeof(bytecode_builder_t));

	if (!bb)
		return NULL;

	bb->arena     = arena;
	bb->capacity  = initial_capacity;
	bb->len       = 0;
	bb->chunk_cnt = 0;

	bb->buf = arena_alloc(arena, initial_capacity);
	if (!bb->buf)
		return NULL;

	return bb;
}

static int
bb_ensure_capacity(bytecode_builder_t *bb, u4 needed)
{
	if (bb->len + needed <= bb->capacity)
		return 0;

	/* grow capacity */
	u4 new_capacity = bb->capacity * 2;
	while (new_capacity < bb->len + needed)
		new_capacity *= 2;

	u1 *new_buf = arena_alloc(bb->arena, new_capacity);
	if (!new_buf)
		return 1;

	/* Copy over existing data */
	memcpy(new_buf, bb->buf, bb->len);
	bb->buf      = new_buf;
	bb->capacity = new_capacity;

	return 0;
}

int
bb_add_template(bytecode_builder_t *bb,
                const bytecode_template_t *tmpl,
                const u2 indices[])
{
	if (bb_ensure_capacity(bb, tmpl->len) != 0)
		return 1;

	/* Copy template bytes */
	memcpy(&bb->buf[bb->len], tmpl->bytes, tmpl->len);

	/* Substitute placeholders */
	for (u2 i = 0; i < tmpl->placeholder_cnt; i++)
	{
		u4 offset = bb->len + tmpl->placeholder_offsets[i];
		u2 idx    = indices[i];

		/* Write big endian */
		bb->buf[offset]     = (u1)(idx >> 8);
		bb->buf[offset + 1] = (u1)(idx & 0xFF);
	}

	bb->len += tmpl->len;
	return 0;
}

int
bb_add_original_chunk(bytecode_builder_t *bb,
                      const u1 *original_code,
                      u4 start_offset,
                      u4 chunk_len)
{
	if (bb_ensure_capacity(bb, chunk_len) != 0)
		return 1;

	if (bb->chunk_cnt < 32)
	{
		pc_chunk_t *chunk     = &bb->chunks[bb->chunk_cnt];
		chunk->original_start = start_offset;
		chunk->original_end   = start_offset + chunk_len;
		chunk->new_start      = bb->len;
		chunk->new_len        = chunk_len;
		bb->chunk_cnt++;
	}

	/* Copy the bytecode */
	memcpy(&bb->buf[bb->len], &original_code[start_offset], chunk_len);
	bb->len += chunk_len;

	return 0;
}

u4
bb_map_pc(const bytecode_builder_t *bb, u4 original_pc)
{
	for (u4 i = 0; i < bb->chunk_cnt; i++)
	{
		const pc_chunk_t *chunk = &bb->chunks[i];

		if (original_pc >= chunk->original_start
		    && original_pc < chunk->original_end)
		{
			u4 offset_in_chunk = original_pc - chunk->original_start;
			return chunk->new_start + offset_in_chunk;
		}
	}

	/* We cannot find pc in any chunk - should not happen */
	return original_pc; /* fallback */
}

int
bb_add_original_with_exit_injection(bytecode_builder_t *bb,
                                    const u1 *original_code,
                                    u4 start_offset,
                                    u4 chunk_len,
                                    const bytecode_template_t *exit_template,
                                    const u2 exit_indices[])
{
	u4 original_pos = 0;
	u4 chunk_start  = bb->len;

	while (original_pos < chunk_len)
	{
		u1 opcode = original_code[start_offset + original_pos];

		/* Is this a return opcode */
		int is_return = 0;
		for (size_t i = 0; i < sizeof(RETURN_OPCODES); i++)
		{
			if (opcode == RETURN_OPCODES[i])
			{
				is_return = 1;
				break;
			}
		}

		if (is_return)
		{
			if (bb_add_template(bb, exit_template, exit_indices) != 0)
				return 1;
		}

		/* Copy original instruction */
		if (bb_ensure_capacity(bb, 1) != 0)
			return 1;

		bb->buf[bb->len++] = opcode;
		original_pos++;
	}

	/* Record chunk mapping */
	if (bb->chunk_cnt < 32)
	{
		pc_chunk_t *chunk     = &bb->chunks[bb->chunk_cnt];
		chunk->original_start = start_offset;
		chunk->original_end   = start_offset + chunk_len;
		chunk->new_start      = chunk_start;
		chunk->new_len        = bb->len - chunk_start;
		bb->chunk_cnt++;
	}

	return 0;
}

static int
create_new_code_attribute(arena_t *arena,
                          class_file_t *cf,
                          method_info_t *method,
                          const bytecode_builder_t *bb,
                          const code_info_t *orig_info)
{
	// /* Calc new attr size:
	// header + new code + exception table + empty attrs */
	// u4 exception_table_sz = orig_info->exception_table_length * 8;
	// u4 new_attr_sz        = 2 + 2 + 4 + bb->len + 2 + exception_table_sz + 2;

	// u1 *new_attr_data = arena_alloc(arena, new_attr_sz);
	// if (!new_attr_data)
	// 	return BYTECODE_ERROR_MEMORY_ALLOCATION;

	// int offset = 0;

	// /* Code attr header */
	// /* Add 3 bytes for injected code */
	// write_u2_and_advance(new_attr_data, &offset, orig_info->max_stack + 3);
	// write_u2_and_advance(new_attr_data, &offset, orig_info->max_locals);
	// write_u4_and_advance(new_attr_data, &offset, bb->len);

	// /* Write the code */
	// memcpy(&new_attr_data[offset], bb->buf, bb->len);
	// offset += bb->len;

	// /* Exception table */
	// write_u2_and_advance(new_attr_data, &offset,
	// orig_info->exception_table_length);

	// if (orig_info->exception_table_length > 0)
	// {
	// 	/* copy original exception table */
	// 	const u1 *orig_table = orig_info->exception_table_data;
	// 	int tbl_offset       = 0;

	// 	for (u2 i = 0; orig_info->exception_table_length; i++)
	// 	{
	// 		u2 start_pc   = read_u2_and_advance(orig_table, &tbl_offset);
	// 		u2 end_pc     = read_u2_and_advance(orig_table, &tbl_offset);
	// 		u2 handler_pc = read_u2_and_advance(orig_table, &tbl_offset);
	// 		u2 catch_type = read_u2_and_advance(orig_table, &tbl_offset);

	// 		/* Map pcs to new locations */
	// 		write_u2_and_advance(
	// 		    new_attr_data, &offset, bb_map_pc(bb, start_pc));
	// 		write_u2_and_advance(
	// 		    new_attr_data, &offset, bb_map_pc(bb, end_pc));
	// 		write_u2_and_advance(
	// 		    new_attr_data, &offset, bb_map_pc(bb, handler_pc));
	// 		write_u2_and_advance(new_attr_data, &offset, catch_type);
	// 	}
	// }

	// /* Empty attributes (removes StackMapTable) */
	// write_u2_and_advance(new_attr_data, &offset, 0);

	// /* Find and update the Code attribute */
	// for (u2 i = 0; i < method->attributes_count; i++)
	// {
	// 	const char *attr_name = bytecode_get_utf8_constant(
	// 	    cf, method->attributes[i].attribute_name_index);

	// 	if (attr_name && strcmp(attr_name, "Code") == 0)
	// 	{
	// 		method->attributes[i].info             = new_attr_data;
	// 		method->attributes[i].attribute_length = new_attr_sz;
	// 		return BYTECODE_SUCCESS;
	// 	}
	// }

	// return BYTECODE_ERROR_CORRUPT_METHODS;
	/* Calculate size without StackMapTable */
	u4 exception_table_sz = orig_info->exception_table_length * 8;
	u4 new_attr_sz        = 2 + 2 + 4 + bb->len + 2 + exception_table_sz + 2;

	u1 *new_attr_data = arena_alloc(arena, new_attr_sz);
	if (!new_attr_data)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset = 0;

	/* Increase stack size for injected code */
	write_u2_and_advance(new_attr_data, &offset, orig_info->max_stack + 3);
	write_u2_and_advance(new_attr_data, &offset, orig_info->max_locals);
	write_u4_and_advance(new_attr_data, &offset, bb->len);

	/* Write modified bytecode */
	memcpy(&new_attr_data[offset], bb->buf, bb->len);
	offset += bb->len;

	/* Copy exception table with PC remapping */
	write_u2_and_advance(new_attr_data, &offset, orig_info->exception_table_length);

	if (orig_info->exception_table_length > 0)
	{
		const u1 *orig_table = orig_info->exception_table_data;
		int tbl_offset       = 0;

		for (u2 i = 0; i < orig_info->exception_table_length; i++)
		{
			u2 start_pc   = read_u2_and_advance(orig_table, &tbl_offset);
			u2 end_pc     = read_u2_and_advance(orig_table, &tbl_offset);
			u2 handler_pc = read_u2_and_advance(orig_table, &tbl_offset);
			u2 catch_type = read_u2_and_advance(orig_table, &tbl_offset);

			/* Remap PCs using bb_map_pc */
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, start_pc));
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, end_pc));
			write_u2_and_advance(
			    new_attr_data, &offset, bb_map_pc(bb, handler_pc));
			write_u2_and_advance(new_attr_data, &offset, catch_type);
		}
	}

	/* No attributes (removes StackMapTable) */
	write_u2_and_advance(new_attr_data, &offset, 0);

	/* Update method's Code attribute */
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);

		if (attr_name && strcmp(attr_name, "Code") == 0)
		{
			method->attributes[i].info             = new_attr_data;
			method->attributes[i].attribute_length = new_attr_sz;
			return BYTECODE_SUCCESS;
		}
	}

	return BYTECODE_ERROR_CORRUPT_METHODS;
}

static attr_info_t *
find_code_attribute(const class_file_t *cf, method_info_t *method)
{
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);

		if (attr_name && strcmp(attr_name, "Code") == 0)
			return &method->attributes[i];
	}

	return NULL;
}

/* Check if Code attribute has StackMapTable */
static int
code_has_stackmap_table(const class_file_t *cf, const code_info_t *info)
{
	if (info->attributes_count == 0)
		return 0;

	int offset          = 0;
	const u1 *attr_data = info->attributes_data;

	for (u2 i = 0; i < info->attributes_count; i++)
	{
		u2 name_index  = read_u2_and_advance(attr_data, &offset);
		u4 attr_length = read_u4_and_advance(attr_data, &offset);

		const char *attr_name = bytecode_get_utf8_constant(cf, name_index);
		if (attr_name && strcmp(attr_name, "StackMapTable") == 0)
			return 1; /* Found StackMapTable */

		offset += attr_length; /* Skip attribute data */
	}

	return 0; /* No StackMapTable found */
}

// TODO move to bytecode and expose in header
/* Parse a code_attr into a code_info struct */
static int
parse_code_attribute(const attr_info_t *code_attr, code_info_t *info)
{
	if (!code_attr || !info)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	int offset        = 0;
	const u1 *data    = code_attr->info;
	info->max_stack   = read_u2_and_advance(data, &offset);
	info->max_locals  = read_u2_and_advance(data, &offset);
	info->code_length = read_u4_and_advance(data, &offset);
	info->bytecode    = &data[offset];
	offset += info->code_length;

	info->exception_table_length = read_u2_and_advance(data, &offset);
	info->exception_table_data   = &data[offset];
	/* Each exception entry is 8 bytes */
	offset += info->exception_table_length * 8;
	info->attributes_count = read_u2_and_advance(data, &offset);
	info->attributes_data  = &data[offset];

	return BYTECODE_SUCCESS;
}

static bytecode_result_e
inject_single_method(arena_t *arena,
                     class_file_t *cf,
                     method_info_t *method,
                     u2 entry_methodref,
                     u2 exit_methodref,
                     u2 class_name_index,
                     u2 method_name_index,
                     u2 descriptor_index)
{
	attr_info_t *code_attr = find_code_attribute(cf, method);
	/* Nothing to do */
	if (!code_attr)
		return BYTECODE_SUCCESS;

	/* Parse the Code attr */
	code_info_t code_info;
	if (parse_code_attribute(code_attr, &code_info) != 0)
		return BYTECODE_ERROR_INVALID_BYTECODE;

	/* Skip methods with StackMapTable for now - they require complex PC remapping */
	if (code_has_stackmap_table(cf, &code_info))
	{
		printf("Skipping method with StackMapTable to avoid verification errors");
		return BYTECODE_SUCCESS;
	}

	/* Build new bytecode */
	bytecode_builder_t *bb = bb_create(arena, code_info.code_length + 64);
	if (!bb)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 entry_indices[] = {
	    class_name_index, method_name_index, descriptor_index, entry_methodref};
	u2 exit_indices[] = {
	    class_name_index, method_name_index, descriptor_index, exit_methodref};

	/* Use template to add new method entry */
	if (bb_add_template(bb, &METHOD_ENTRY_TEMPLATE, entry_indices) != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	// /* Add original code */
	// if (bb_add_original_chunk(bb, code_info.bytecode, 0, code_info.code_length) !=
	// 0) 	return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add original code with exit injection */
	if (bb_add_original_with_exit_injection(bb,
	                                        code_info.bytecode,
	                                        0,
	                                        code_info.code_length,
	                                        &METHOD_EXIT_TEMPLATE,
	                                        exit_indices)
	    != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Add new Code attribute */
	if (create_new_code_attribute(arena, cf, method, bb, &code_info) != 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_add_method_tracking_clean(arena_t *arena,
                                    class_file_t *cf,
                                    injection_config_t *cfg)
{
	const char *class_name = bytecode_get_class_name(cf);
	if (!class_name)
		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

	u2 class_idx = injection_find_or_add_string_constant(arena, cf, class_name);
	if (class_idx == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 entry_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, cfg->callback_class, cfg->entry_method, cfg->entry_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 exit_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, cfg->callback_class, cfg->exit_method, cfg->exit_sig);

	if (exit_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Inject */
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *method_name = bytecode_get_method_name(cf, i);

		/* ignore ctor */
		if (method_name && strcmp(method_name, "<clinit>") != 0)
		{
			u2 method_name_idx =
			    injection_find_or_add_string_constant(arena, cf, method_name);
			if (method_name_idx == 0)
				continue;

			/* Get method descriptor */
			const char *method_descriptor = bytecode_get_utf8_constant(
			    cf, cf->methods[i].descriptor_index);
			if (!method_descriptor)
				continue;

			u2 descriptor_string_idx = injection_find_or_add_string_constant(
			    arena, cf, method_descriptor);
			if (descriptor_string_idx == 0)
				continue;

			bytecode_result_e res =
			    inject_single_method(arena,
			                         cf,
			                         &cf->methods[i],
			                         entry_methodref,
			                         exit_methodref,
			                         class_idx,
			                         method_name_idx,
			                         descriptor_string_idx);

			if (res != BYTECODE_SUCCESS)
				return res;
		}
	}

	return BYTECODE_SUCCESS;
}

// static bytecode_result_e
// inject_method_bytecode(arena_t *arena,
//                        class_file_t *cf,
//                        method_info_t *method,
//                        u2 entry_method_ref,
//                        u2 exit_method_ref,
//                        u2 class_name_index,
//                        u2 method_name_index)
// {

// 	assert(arena != NULL);
// 	assert(cf != NULL);
// 	assert(method != NULL);

// 	/* Find code attr */
// 	attr_info_t *code_attr = NULL;
// 	for (u2 i = 0; i < method->attributes_count; i++)
// 	{
// 		const char *attr_name = bytecode_get_utf8_constant(
// 		    cf, method->attributes[i].attribute_name_index);
// 		if (attr_name && strcmp(attr_name, "Code") == 0)
// 		{
// 			code_attr = &method->attributes[i];
// 			break;
// 		}
// 	}

// 	/* Abstract or native method - skip */
// 	if (!code_attr)
// 		return BYTECODE_SUCCESS;

// 	/* Parse the existing Code attribute
// 	https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.3
// 	Code_attribute {
// 	    u2 attribute_name_index;
// 	    u4 attribute_length;
// 	    u2 max_stack;
// 	    u2 max_locals;
// 	    u4 code_length;
// 	    u1 code[code_length];
// 	    u2 exception_table_length;
// 	    {   u2 start_pc;
// 	        u2 end_pc;
// 	        u2 handler_pc;
// 	        u2 catch_type;
// 	    } exception_table[exception_table_length];
// 	    u2 attributes_count;
// 	    attribute_info attributes[attributes_count];
// 	}
// 	*/
// 	int offset          = 0;
// 	const u1 *code_data = code_attr->info;
// 	u2 max_stack        = read_u2_and_advance(code_data, &offset);
// 	u2 max_locals       = read_u2_and_advance(code_data, &offset);
// 	u4 code_len         = read_u4_and_advance(code_data, &offset);
// 	/* Beginning of byte array containing the method */
// 	const u1 *existing_code = &code_data[offset];
// 	offset += code_len;

// 	/* Skip exception table and atributes for now */
// 	u2 exception_table_len = read_u2_and_advance(code_data, &offset);
// 	/* Each exception entry is 8 bytes */
// 	offset += exception_table_len * 8;

// 	u2 code_attributes_count = read_u2_and_advance(code_data, &offset);

// 	/* Skip code attributes */
// 	for (u2 i = 0; i < code_attributes_count; i++)
// 	{
// 		offset += 2; /* attribute_name_index */
// 		u4 attr_len = read_u4_and_advance(code_data, &offset);
// 		offset += attr_len;
// 	}

// 	if (class_name_index == 0 || class_name_index >= cf->constant_pool_count
// 	    || cf->constant_pool[class_name_index].tag != CONSTANT_String)
// 	{
// 		printf("ERROR: Invalid class_name_index=%d\n", class_name_index);
// 		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
// 	}

// 	if (method_name_index == 0 || method_name_index >= cf->constant_pool_count
// 	    || cf->constant_pool[method_name_index].tag != CONSTANT_String)
// 	{
// 		printf("ERROR: Invalid method_name_index=%d\n", method_name_index);
// 		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
// 	}

// 	const char *method_descriptor =
// 	    bytecode_get_utf8_constant(cf, method->descriptor_index);
// 	if (!method_descriptor)
// 	{
// 		printf("ERROR: Could not get method descriptor\n");
// 		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;
// 	}

// 	u2 descriptor_string_index =
// 	    injection_find_or_add_string_constant(arena, cf, method_descriptor);
// 	if (descriptor_string_index == 0)
// 	{
// 		printf("ERROR: Could not create descriptor string constant\n");
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;
// 	}

// 	// TODO refactor this into a function?
// 	/* Build entry injection bytecode:
// 	 * ldc_w #class_name_index    (3 bytes)
// 	 * ldc_w #method_name_index   (3 bytes)
// 	 * ldc_w #method_descriptor   (3 bytes)
// 	 * invokestatic #entry_methodref (3 bytes)
// 	 * Total: 12 bytes
// 	 */
// 	/* clang-format off */
// 	u1 entry_injection[12] =
// 	{
// 	    0x13, (u1)(class_name_index >> 8), (u1)(class_name_index & 0xFF), /* ldc_w
// class_name */ 	    0x13, (u1)(method_name_index >> 8), (u1)(method_name_index &
// 0xFF), /* ldc_w method_name */ 	    0x13, (u1)(method->descriptor_index >> 8),
// (u1)(descriptor_string_index& 0xFF), /* ldc_w method_descriptor */ 	    0xB8,
// (u1)(entry_method_ref >> 8), (u1)(entry_method_ref & 0xFF) /* invokestatic entry_method
// */
// 	};
// 	/* clang-format on */

// 	/* Build exit injection for return instructions:
// 	 * Similar to entry but for exit callback
// 	 */
// 	/* clang-format off */
// 	u1 exit_injection[12] =
// 	{
// 	    0x13, (u1)(class_name_index >> 8), (u1)(class_name_index & 0xFF), /* ldc_w
// class_name */ 	    0x13, (u1)(method_name_index >> 8), (u1)(method_name_index &
// 0xFF), /* ldc_w method_name */ 	    0x13, (u1)(method->descriptor_index >> 8),
// (u1)(descriptor_string_index & 0xFF), /* ldc_w method_descriptor */ 	    0xB8,
// (u1)(exit_method_ref >> 8), (u1)(exit_method_ref & 0xFF) /* invokestatic exit_method */
// 	};
// 	/* clang-format on */

// 	/* Calculate new size - estimate */
// 	u4 estimated_new_sz = code_len + sizeof(entry_injection);

// 	/* Scan for return instructions to inject exit calls */
// 	u4 return_count = 0;
// 	for (u4 i = 0; i < code_len; i++)
// 	{
// 		u1 opcode = existing_code[i];
// 		if (opcode == 0xB1 || /* return */
// 		    opcode == 0xAC || /* ireturn */
// 		    opcode == 0xAD || /* lreturn */
// 		    opcode == 0xAE || /* freturn */
// 		    opcode == 0xAF || /* dreturn */
// 		    opcode == 0xB0)
// 		{ /* areturn */
// 			return_count++;
// 		}
// 	}

// 	estimated_new_sz += return_count * sizeof(exit_injection);

// 	/* Create new code buffer */
// 	u1 *new_code = arena_alloc(arena, estimated_new_sz);
// 	if (!new_code)
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;

// 	pc_mapping_t *pc_map = arena_alloc(arena, code_len * sizeof(pc_mapping_t));
// 	u4 map_count         = 0;

// 	u4 new_code_pos     = 0;
// 	u4 injection_offset = sizeof(entry_injection);

// 	/* Inject entry tracking at method start */
// 	memcpy(&new_code[new_code_pos], entry_injection, sizeof(entry_injection));
// 	new_code_pos += sizeof(entry_injection);

// 	/* Copy exiting bytecode,
// 	injecting the exit calls before returns */
// 	for (u4 i = 0; i < code_len; i++)
// 	{
// 		u1 opcode = existing_code[i];

// 		/* Record PC mapping */
// 		pc_map[map_count].original_pc = i;
// 		pc_map[map_count].new_pc      = new_code_pos;
// 		map_count++;

// 		/* Check if opcode is a return */
// 		if (opcode == 0xB1 || /* return */
// 		    opcode == 0xAC || /* ireturn */
// 		    opcode == 0xAD || /* lreturn */
// 		    opcode == 0xAE || /* freturn */
// 		    opcode == 0xAF || /* dreturn */
// 		    opcode == 0xB0)   /* areturn */
// 		{
// 			/* inject exit tracking */
// 			memcpy(&new_code[new_code_pos],
// 			       exit_injection,
// 			       sizeof(exit_injection));
// 			new_code_pos += sizeof(exit_injection);
// 		}

// 		/* Copy original instruction */
// 		new_code[new_code_pos++] = opcode;

// 		// /* Handle instructions with operands
// 		// simplified for common cases
// 		// TODO: Complete instruction parsing for precise operand handling
// 		// */
// 		// switch (opcode)
// 		// {
// 		// 	case 0x10: /* bipush */
// 		// 	case 0x12: /* ldc */
// 		// 		new_code[new_code_pos++] =
// 		// 		    existing_code[++i]; /* 1 operand byte */
// 		// 		break;
// 		// 	case 0x11: /* sipush */
// 		// 	case 0x13: /* ldc_w */
// 		// 	case 0x14: /* ldc2_w */
// 		// 		new_code[new_code_pos++] =
// 		// 		    existing_code[++i]; /*2 operand byte */
// 		// 		new_code[new_code_pos++] = existing_code[++i];
// 		// 		break;
// 		// 		/* Add more operand handling as required... */
// 		// }
// 	}

// 	u4 final_new_code_len = new_code_pos;

// 	u2 orig_exception_count = read_u2_and_advance(code_data, &offset);

// 	/* Create new Code attribute */
// 	u4 new_attr_len = 12 + final_new_code_len + 2 + (orig_exception_count * 8) + 2;
// 	/*                ^   ^                     ^   ^                           ^
// 	          |   |                     |   |                           |
// 	          |   code bytes            |   exception entries attributes_count header
// 	   exception_table_length
// 	*/

// 	/* Code attr header + new code + empty exception/attr tables */
// 	u1 *new_attr_data = arena_alloc(arena, new_attr_len);
// 	if (!new_attr_data)
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;

// 	int attr_offset = 0;
// 	/* We need to increase the stack for our code */
// 	write_u2_and_advance(new_attr_data, &attr_offset, max_stack + 3);
// 	write_u2_and_advance(new_attr_data, &attr_offset, max_locals);
// 	write_u4_and_advance(new_attr_data, &attr_offset, final_new_code_len);
// 	memcpy(&new_attr_data[attr_offset], new_code, final_new_code_len);
// 	attr_offset += final_new_code_len;

// 	/* Empty exception table for now */
// 	// write_u2_and_advance(new_attr_data, &attr_offset, 0); /* exception_table_len */
// 	// write_u2_and_advance(new_attr_data, &attr_offset, 0); /* attributes_count */

// 	write_u2_and_advance(new_attr_data, &attr_offset, orig_exception_count);

// 	/* copy exception table and adjust */
// 	for (u2 i = 0; i < orig_exception_count; i++)
// 	{
// 		u2 start_pc   = read_u2_and_advance(code_data, &offset);
// 		u2 end_pc     = read_u2_and_advance(code_data, &offset);
// 		u2 handler_pc = read_u2_and_advance(code_data, &offset);
// 		u2 catch_type = read_u2_and_advance(code_data, &offset);

// 		u4 new_start_pc   = find_new_pc(pc_map, map_count, start_pc);
// 		u4 new_end_pc     = find_new_pc(pc_map, map_count, end_pc);
// 		u4 new_handler_pc = find_new_pc(pc_map, map_count, handler_pc);

// 		/* Now we adjust with the offset */
// 		write_u2_and_advance(new_attr_data, &attr_offset, new_start_pc);
// 		write_u2_and_advance(new_attr_data, &attr_offset, new_end_pc);
// 		write_u2_and_advance(new_attr_data, &attr_offset, new_handler_pc);
// 		write_u2_and_advance(new_attr_data, &attr_offset, catch_type);
// 	}

// 	/* Skip Code attributes for now (remove StackMapTable) */
// 	write_u2_and_advance(new_attr_data, &attr_offset, 0);

// 	/* Update the method's Code attribute */
// 	code_attr->info             = new_attr_data;
// 	code_attr->attribute_length = new_attr_len;

// 	return BYTECODE_SUCCESS;
// }

void
debug_constant_pool_indices(class_file_t *cf, u2 class_idx, u2 method_idx)
{
	printf("=== CONSTANT POOL DEBUG ===\n");
	printf("Total entries: %d\n", cf->constant_pool_count);
	printf("Looking for class_idx=%d, method_idx=%d\n", class_idx, method_idx);

	/* Check the specific indices being used in bytecode */
	for (u2 i = 5; i <= 10; i++)
	{ /* Indices 5,6,8 from your bytecode */
		if (i < cf->constant_pool_count)
		{
			printf("Index %d: tag=%d", i, cf->constant_pool[i].tag);
			if (cf->constant_pool[i].tag == CONSTANT_Utf8)
			{
				printf(" UTF8='%s'",
				       (char *)cf->constant_pool[i].info.utf8.bytes);
			}
			printf("\n");
		}
		else
		{
			printf("Index %d: OUT OF BOUNDS\n", i);
		}
	}
	printf("===========================\n");
}

// bytecode_result_e
// injection_add_method_tracking(arena_t *arena,
//                               class_file_t *cf,
//                               injection_config_t *config)
// {
// 	assert(arena != NULL);
// 	assert(cf != NULL);
// 	assert(config != NULL);

// 	/* Get class name for callbacks */
// 	const char *class_name = bytecode_get_class_name(cf);
// 	if (!class_name)
// 		return BYTECODE_ERROR_CORRUPT_CONSTANT_POOL;

// 	u2 class_name_idx = injection_find_or_add_string_constant(arena, cf, class_name);
// 	if (class_name_idx == 0)
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;

// 	/* Add required constant pool entries */
// 	u2 entry_methodref = injection_find_or_add_methodref_constant(
// 	    arena, cf, config->callback_class, config->entry_method, config->entry_sig);

// 	if (entry_methodref == 0)
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;

// 	u2 exit_methodref = injection_find_or_add_methodref_constant(
// 	    arena, cf, config->callback_class, config->exit_method, config->exit_sig);

// 	if (exit_methodref == 0)
// 		return BYTECODE_ERROR_MEMORY_ALLOCATION;

// 	size_t methods_modified = 0;
// 	/* Now inject the tracking into all methods */
// 	for (u2 i = 0; i < cf->methods_count; i++)
// 	{
// 		const char *method_name = bytecode_get_method_name(cf, i);
// 		/* Inject into every method apart from ctor */
// 		if (method_name && strcmp(method_name, "<clinit>") != 0)
// 		{
// 			u2 method_name_idx =
// 			    injection_find_or_add_string_constant(arena, cf, method_name);

// 			debug_constant_pool_indices(cf, class_name_idx, method_name_idx);

// 			if (method_name_idx == 0)
// 				continue;

// 			bytecode_result_e res = inject_method_bytecode(arena,
// 			                                               cf,
// 			                                               &cf->methods[i],
// 			                                               entry_methodref,
// 			                                               exit_methodref,
// 			                                               class_name_idx,
// 			                                               method_name_idx);

// 			if (res != BYTECODE_SUCCESS)
// 				return res;

// 			methods_modified++;
// 		}
// 	}

// 	return BYTECODE_SUCCESS;
// }