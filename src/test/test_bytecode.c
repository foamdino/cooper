/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <sys/stat.h>

#include "../lib/jvm/bytecode.h"
#include "../lib/jvm/injection.h"

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

	class_file_t *cf = NULL;
	bytecode_result_e result =
	    bytecode_parse_class(arena, class_data, class_size, &cf);
	if (result != BYTECODE_SUCCESS)
	{
		printf("Parse failed: %d\n", result);
		arena_destroy(arena);
		free(class_data);
		return -1;
	}

	printf("Original class parsed successfully\n");
	bytecode_print_class_info(cf);
	/* Show details for first few methods BEFORE injection */
	printf("\nBEFORE injection - Method details:\n");
	for (u2 i = 0; i < (cf->methods_count < 3 ? cf->methods_count : 3); i++)
	{
		bytecode_print_method_details(cf, i);
	}

	/* Configure injection */
	injection_config_t config = {
	    .callback_class = "com/myagent/MethodTracker",
	    .entry_method   = "onEntry",
	    .exit_method    = "onExit",
	    .entry_sig      = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
	    .exit_sig = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"};

	printf("\nInjecting method tracking...\n");
	result = injection_add_method_tracking_clean(arena, cf, &config);
	if (result != BYTECODE_SUCCESS)
	{
		printf("Injection failed: %d\n", result);
		arena_destroy(arena);
		free(class_data);
		return -1;
	}

	printf("Injection completed!\n");
	bytecode_print_class_info(cf);
	printf("\nAFTER injection - Method details:\n");
	for (u2 i = 0; i < (cf->methods_count < 3 ? cf->methods_count : 3); i++)
	{
		bytecode_print_method_details(cf, i);
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