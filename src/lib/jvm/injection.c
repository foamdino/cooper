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

static bytecode_result_e
inject_method_bytecode(arena_t *arena,
                       class_file_t *cf,
                       method_info_t *method,
                       u2 entry_method_ref,
                       u2 exit_method_ref)
{

	assert(arena != NULL);
	assert(cf != NULL);
	assert(method != NULL);

	/* Find code attr */
	attr_info_t *code_attr = NULL;
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);
		if (attr_name && strcmp(attr_name, "Code") == 0)
		{
			code_attr = &method->attributes[i];
			break;
		}
	}

	/* Abstract or native method - skip */
	if (!code_attr)
		return BYTECODE_SUCCESS;

	/* Parse the existing Code attribute
	https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.3
	Code_attribute {
	    u2 attribute_name_index;
	    u4 attribute_length;
	    u2 max_stack;
	    u2 max_locals;
	    u4 code_length;
	    u1 code[code_length];
	    u2 exception_table_length;
	    {   u2 start_pc;
	        u2 end_pc;
	        u2 handler_pc;
	        u2 catch_type;
	    } exception_table[exception_table_length];
	    u2 attributes_count;
	    attribute_info attributes[attributes_count];
	}
	*/
	int offset          = 0;
	const u1 *code_data = code_attr->info;
	u2 max_stack        = read_u2_and_advance(code_data, &offset);
	u2 max_locals       = read_u2_and_advance(code_data, &offset);
	u4 code_len         = read_u4_and_advance(code_data, &offset);
	/* Beginning of byte array containing the method */
	const u1 *existing_code = &code_data[offset];

	/* Calculate the size of new bytecode */
	/* Entry:
	ldc class_name, ldc method_name, ldc method_sig, invokestatic
	*/
	u4 entry_injection_sz = 8; // approx

	/* Exit:
	ldc class_name, ldc method_name, ldc method_sig, invokestatic
	*/
	u4 exit_injection_sz = 8; // approx

	u4 new_code_len = code_len + entry_injection_sz;

	/* Create new buffer */
	u1 *new_code = arena_alloc(arena, new_code_len);
	if (!new_code)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Inject entry tracking at method start */
	// TODO actually inject new code here
	memcpy(new_code, existing_code, code_len);

	/* Create a new Code attribute */
	u4 new_attr_len   = 12 + new_code_len; /* Code attr header + code */
	u1 *new_attr_data = arena_alloc(arena, new_attr_len);
	if (!new_attr_data)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	offset = 0;
	write_u2_and_advance(new_attr_data, &offset, max_stack + 3);
	write_u2_and_advance(new_attr_data, &offset, max_locals);
	write_u4_and_advance(new_attr_data, &offset, new_code_len);
	memcpy(&new_attr_data[offset], new_code, new_code_len);
	offset += new_code_len;

	/* Exception table, copy as-is for now */
	write_u2_and_advance(new_attr_data, &offset, 0); /* exception_table_len */
	write_u2_and_advance(new_attr_data, &offset, 0); /* attributes_count */

	/* Update the method's Code attribute */
	code_attr->info             = new_attr_data;
	code_attr->attribute_length = new_attr_len;

	return BYTECODE_SUCCESS;
}

bytecode_result_e
injection_add_method_tracking(arena_t *arena,
                              class_file_t *cf,
                              injection_config_t *config)
{
	assert(arena != NULL);
	assert(cf != NULL);
	assert(config != NULL);

	/* Add required constant pool entries */
	u2 entry_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, config->callback_class, config->entry_method, config->entry_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	u2 exit_methodref = injection_find_or_add_methodref_constant(
	    arena, cf, config->callback_class, config->exit_method, config->exit_sig);

	if (entry_methodref == 0)
		return BYTECODE_ERROR_MEMORY_ALLOCATION;

	/* Now inject the tracking into all methods */
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *method_name = bytecode_get_method_name(cf, i);
		/* Inject into every method apart from ctor */
		if (method_name && strcmp(method_name, "<clinit>") != 0)
		{
			bytecode_result_e res = inject_method_bytecode(
			    arena, cf, &cf->methods[i], entry_methodref, exit_methodref);

			if (res != BYTECODE_SUCCESS)
				return res;
		}
	}

	return BYTECODE_SUCCESS;
}