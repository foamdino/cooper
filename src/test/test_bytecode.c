/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sys/stat.h>

#include "../lib/jvm/bytecode.h"
#include "../lib/jvm/injection.h"

void
print_class_info(const class_file_t *cf)
{
	printf("Class File Information:\n");
	printf("  Magic: 0x%08X\n", cf->magic);
	printf("  Version: %d.%d\n", cf->major_version, cf->minor_version);
	printf("  Class: %s\n", bytecode_get_class_name(cf));
	printf("  Constant Pool: %d entries\n", cf->constant_pool_count - 1);
	printf("  Methods: %d\n", cf->methods_count);
	printf("  Fields: %d\n", cf->fields_count);
	printf("  Attributes: %d\n", cf->attributes_count);

	printf("\nMethods:\n");
	for (u2 i = 0; i < cf->methods_count; i++)
	{
		const char *name =
		    bytecode_get_utf8_constant(cf, cf->methods[i].name_index);
		const char *desc =
		    bytecode_get_utf8_constant(cf, cf->methods[i].descriptor_index);
		printf("[%d] %s %s\n", i, name ? name : "?", desc ? desc : "?");
	}
	printf("\nAttributes:\n");
	for (u2 i = 0; i < cf->attributes_count; i++)
	{
		const char *name = bytecode_get_utf8_constant(
		    cf, cf->attributes[i].attribute_name_index);
		printf("[%d] %s\n", i, name ? name : "?");
	}
}

void
print_method_details(const class_file_t *cf, u2 method_idx)
{
	if (method_idx >= cf->methods_count)
	{
		printf("Invalid method index: %d\n", method_idx);
		return;
	}

	const method_info_t *method = &cf->methods[method_idx];
	const char *name            = bytecode_get_method_name(cf, method_idx);
	char *desc                  = "?";
	printf("\nMethod [%d]: %s%s\n", method_idx, name ? name : "?", desc ? desc : "?");
	printf("  Access flags: 0x%04X\n", method->access_flags);
	printf("  Attributes: %d\n", method->attributes_count);

	/* Look for Code attribute */
	for (u2 i = 0; i < method->attributes_count; i++)
	{
		const char *attr_name = bytecode_get_utf8_constant(
		    cf, method->attributes[i].attribute_name_index);
		printf("    [%d] %s (length: %d)\n",
		       i,
		       attr_name ? attr_name : "?",
		       method->attributes[i].attribute_length);

		if (attr_name && strcmp(attr_name, "Code") == 0)
		{
			/* Parse Code attribute to show bytecode size */
			int offset          = 0;
			const u1 *code_data = method->attributes[i].info;
			u2 max_stack        = read_u2_and_advance(code_data, &offset);
			u2 max_locals       = read_u2_and_advance(code_data, &offset);
			u4 code_length      = read_u4_and_advance(code_data, &offset);

			printf("      Max stack: %d, Max locals: %d\n",
			       max_stack,
			       max_locals);
			printf("      Bytecode length: %d bytes\n", code_length);

			/* Show first few bytes of bytecode */
			printf("      First 16 bytes: ");
			for (u4 j = 0; j < 16 && j < code_length; j++)
				printf("%02X ", code_data[offset + j]);

			printf("\n");
		}
	}
}

/* Read entire file into buffer */
static u1 *
read_file(const char *filename, u4 *size)
{
	FILE *file = fopen(filename, "rb");
	if (!file)
	{
		printf("Failed to open file: %s\n", filename);
		return NULL;
	}

	struct stat st;
	if (stat(filename, &st) != 0)
	{
		fclose(file);
		return NULL;
	}

	*size      = st.st_size;
	u1 *buffer = malloc(*size);
	if (!buffer)
	{
		fclose(file);
		return NULL;
	}

	if (fread(buffer, 1, *size, file) != *size)
	{
		free(buffer);
		fclose(file);
		return NULL;
	}

	fclose(file);
	return buffer;
}

static int
test_injection(const char *filename)
{
	/* Read and parse class */
	u4 class_size;
	u1 *class_data = read_file(filename, &class_size);
	if (!class_data)
		return -1;

	arena_t *arena =
	    arena_init("class-arena", 4 * 1024 * 1024, 1024); /* 4MB for modifications */
	if (!arena)
	{
		free(class_data);
		return -1;
	}

	class_file_t *cf         = NULL;
	bytecode_result_e result = bytecode_parse_class(arena, class_data, &cf);
	if (result != BYTECODE_SUCCESS)
	{
		printf("Parse failed: %d\n", result);
		arena_destroy(arena);
		free(class_data);
		return -1;
	}

	printf("Original class parsed successfully\n");
	print_class_info(cf);
	/* Show details for first few methods BEFORE injection */
	printf("\nBEFORE injection - Method details:\n");
	for (u2 i = 0; i < (cf->methods_count < 3 ? cf->methods_count : 3); i++)
	{
		print_method_details(cf, i);
	}

	/* Configure injection */
	injection_config_t config = {
	    .callback_class = "com/myagent/MethodTracker",
	    .entry_method   = "onEntry",
	    .exit_method    = "onExit",
	    .entry_sig      = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
	    .exit_sig = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"};

	printf("\nInjecting method tracking...\n");
	result = injection_add_method_tracking(arena, cf, &config);
	if (result != BYTECODE_SUCCESS)
	{
		printf("Injection failed: %d\n", result);
		arena_destroy(arena);
		free(class_data);
		return -1;
	}

	printf("Injection completed!\n");
	print_class_info(cf);
	printf("\nAFTER injection - Method details:\n");
	for (u2 i = 0; i < (cf->methods_count < 3 ? cf->methods_count : 3); i++)
	{
		print_method_details(cf, i);
	}

	arena_destroy(arena);
	free(class_data);
	return 0;
}

int
main()
{
	test_injection("com/github/foamdino/Test.class");

	return 0;
}