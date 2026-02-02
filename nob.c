/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// This is your build script. You only need to "bootstrap" it once with `cc -o nob nob.c`
// (you can call it whatever actually) or `cl nob.c` on MSVC and thanks to
// NOB_GO_REBUILD_URSELF (see below). After that every time you run the `nob` executable
// if it detects that you modifed nob.c it will rebuild itself automatically

// nob.h is an stb-style library
// https://github.com/nothings/stb/blob/master/docs/stb_howto.txt What that means is that
// it's a single file that acts both like .c and .h files, but by default when you include
// it, it acts only as .h. To make it include implementations of the functions you must
// define NOB_IMPLEMENTATION macro. This is done to give you full control over where the
// implementations go.
#define NOB_IMPLEMENTATION

// Always keep a copy of nob.h in your repo. One of my main pet peeves with build systems
// like CMake and Autotools is that the codebases that use them naturally rot. That is if
// you do not actively update your build scripts, they may not work with the latest
// version of the build tools. Here we basically include the entirety of the source code
// of the tool along with the code base. It will never get outdated.
//
// (In these examples we actually symlinking nob.h, but this is to keep nob.h-s synced
// among all the examples)
#include "nob.h"

#include <stdlib.h>
#include <sys/stat.h>

// TODO: add more comments in here

#define BUILD_FOLDER "build/"
#define SRC_FOLDER   "src/"
#define JAVA_SRC     "java-src/"

// Subdirs for organisational clarity
#define LIB_FOLDER   SRC_FOLDER "lib/"
#define AGENT_FOLDER SRC_FOLDER "agent/"
#define CLI_FOLDER   SRC_FOLDER "cli/"
#define TEST_FOLDER  SRC_FOLDER "test/"

static bool
path_is_dir(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return false;
	return S_ISDIR(st.st_mode);
}

static void
add_sources_from_dir(Nob_Cmd *cmd, const char *dir)
{
	Nob_File_Paths paths = {0};
	if (!nob_read_entire_dir(dir, &paths))
	{
		nob_log(NOB_ERROR, "Failed to read dir %s", dir);
		exit(1);
	}

	for (size_t i = 0; i < paths.count; ++i)
	{
		const char *item = paths.items[i];
		if (strcmp(item, ".") == 0 || strcmp(item, "..") == 0)
		{
			continue; // Skip the current and parent directory entries
		}

		char full_path[1024];

		// add slash if not already present
		size_t len = strlen(dir);
		if (len > 0 && dir[len - 1] == '/')
			snprintf(
			    full_path, sizeof(full_path), "%s%s", dir, paths.items[i]);
		else
			snprintf(
			    full_path, sizeof(full_path), "%s/%s", dir, paths.items[i]);

		if (path_is_dir(full_path))
		{
			// recurse into subdir
			add_sources_from_dir(cmd, full_path);
		}
		else if (nob_sv_end_with(nob_sv_from_cstr(paths.items[i]), ".c"))
		{
			// add .c source file
			nob_cmd_append(cmd, nob_temp_strdup(full_path));
		}
	}
}

// ... (previous code)

void
gen_compile_commands(Nob_Cmd cmd, const char *output_filename)
{
	FILE *f = fopen(output_filename, "a");
	if (f == NULL)
	{
		nob_log(NOB_ERROR, "Could not open file %s", output_filename);
		return;
	}

	// We need to iterate over the command arguments to find source files
	// and write a JSON entry for each one.
	// This is a simplified implementation that assumes the last argument is NOT the
	// source file if there are multiple source files, which is true for how we use it
	// (we append sources at the end usually, but sometimes flags come after).
	// Actually, nob_cmd_append appends to the dynamic array.

	// A robust way for this specific build script:
	// We know we are adding sources via add_sources_from_dir or manually.
	// We can iterate the cmd.items and check for .c extension.

	for (size_t i = 0; i < cmd.count; ++i)
	{
		const char *arg = cmd.items[i];
		if (nob_sv_end_with(nob_sv_from_cstr(arg), ".c"))
		{
			// It's a source file. Write an entry.
			// If it's not the first entry in the file, we might need a comma,
			// but we are appending to a file that starts with '['.
			// To handle commas correctly, we can check file position or just
			// handle it in main. For simplicity, let's assume main handles
			// the opening '[' and we prepend a comma if needed. But we don't
			// know if we are the first. Let's just write the entry and let
			// main handle the commas? No, main calls this multiple times.

			// Let's make this function just append the entry.
			// We will handle the comma logic by checking if the file is empty
			// (just '[')? Easier: Main writes '['. This function writes ", {
			// ... }" But for the very first item, we don't want a comma. This
			// is getting slightly complex for a simple append.

			// Alternative: Build a large string in memory? No.

			// Let's just write ",\n" BEFORE the entry.
			// Main writes "[ \n".
			// Then we have entries.
			// The first entry will look like "[ \n , { ...". This is invalid
			// JSON. We need a state.

			// Let's change the signature to accept a bool *first_entry.
		}
	}
	fclose(f);
}

// Re-implementing with state
void
append_compile_command(FILE *f, Nob_Cmd cmd, const char *source_file, bool *first)
{
	if (!*first)
	{
		fprintf(f, ",\n");
	}
	*first = false;

	fprintf(f, "  {\n");
	fprintf(f, "    \"directory\": \"%s\",\n", nob_get_current_dir_temp());
	fprintf(f, "    \"file\": \"%s\",\n", source_file);
	fprintf(f, "    \"command\": \"");

	// 1. Compiler
	fprintf(f, "%s", cmd.items[0]);

	// 2. Flags (skip -o and .c files)
	for (size_t i = 1; i < cmd.count; ++i)
	{
		const char *arg = cmd.items[i];

		if (strcmp(arg, "-o") == 0)
		{
			i++; // Skip the output filename
			continue;
		}

		if (nob_sv_end_with(nob_sv_from_cstr(arg), ".c"))
		{
			continue; // Skip other source files
		}

		fprintf(f, " ");

		// Simple escaping for quotes and backslashes
		for (size_t j = 0; j < strlen(arg); ++j)
		{
			if (arg[j] == '"' || arg[j] == '\\')
			{
				fprintf(f, "\\");
			}
			fprintf(f, "%c", arg[j]);
		}
	}

	// 3. Append -c <source_file>
	fprintf(f, " -c %s", source_file);

	// 4. Append -o build/<basename>.o
	const char *filename = strrchr(source_file, '/');
	if (filename)
		filename++;
	else
		filename = source_file;

	// Create object filename (replace .c with .o)
	// We know source_file ends in .c because of the caller check
	size_t len = strlen(filename);
	char obj_name[len + 1];
	strcpy(obj_name, filename);
	if (len > 2)
	{
		obj_name[len - 1] = 'o'; // replace 'c' with 'o'
	}

	fprintf(f, " -o build/%s", obj_name);

	fprintf(f, "\"\n");
	fprintf(f, "  }");
}

void
gen_compile_commands_for_cmd(Nob_Cmd cmd, FILE *f, bool *first)
{
	for (size_t i = 0; i < cmd.count; ++i)
	{
		const char *arg = cmd.items[i];
		if (nob_sv_end_with(nob_sv_from_cstr(arg), ".c"))
		{
			append_compile_command(f, cmd, arg, first);
		}
	}
}

int
main(int argc, char **argv)
{
	NOB_GO_REBUILD_URSELF(argc, argv);

	Nob_Cmd cc_cmd            = {0};
	Nob_Cmd javac_cmd         = {0};
	Nob_Cmd test_cmd          = {0};
	Nob_Cmd cli_cmd           = {0};
	Nob_Cmd tui_cmd           = {0};
	Nob_Cmd test_bytecode_cmd = {0};

	const char *JAVA_HOME = getenv("JAVA_HOME");
	assert(JAVA_HOME != NULL);

	int j_buf_sz = strlen(JAVA_HOME) + strlen("/include") + 3;
	char JAVA_INC[j_buf_sz];
	snprintf(JAVA_INC, j_buf_sz, "-I%s/%s", JAVA_HOME, "include");

	int l_buf_sz = strlen(JAVA_HOME) + strlen("/include") + strlen("/linux") + 3;
	char LINUX_INC[l_buf_sz];
	snprintf(LINUX_INC, l_buf_sz, "-I%s/%s/%s", JAVA_HOME, "include", "linux");

	/* Check that the build output dir exists */
	if (!nob_mkdir_if_not_exists(BUILD_FOLDER))
		return 1;

	// Check for debug build
	int debug_build = 0;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--debug") == 0)
		{
			debug_build = 1;
			break;
		}
	}

	nob_cmd_append(&cc_cmd,
	               "cc",
	               "-Wall",
	               "-Wextra",
	               "-shared",
	               "-fPIC",
	               JAVA_INC,
	               LINUX_INC,
	               "-I.");

	if (debug_build)
	{
		nob_cmd_append(
		    &cc_cmd, "-DENABLE_DEBUG_LOGS", "-DENABLE_INFO_LOGS", "-g");
		printf("Building in DEBUG mode with logs enabled\n");
	}
	else
		nob_cmd_append(&cc_cmd, "-DENABLE_INFO_LOGS", "-O2");

	nob_cmd_append(&cc_cmd, "-o", BUILD_FOLDER "libcooper.so");
	add_sources_from_dir(&cc_cmd, LIB_FOLDER);
	add_sources_from_dir(&cc_cmd, AGENT_FOLDER);
	// add_sources_from_dir(&cc_cmd, SRC_FOLDER);
	nob_cmd_append(&cc_cmd, "-pthread", "-lrt");

	if (!nob_cmd_run_sync(cc_cmd))
		return 1;

	/* compile java */
	nob_cmd_append(&javac_cmd,
	               "javac",
	               JAVA_SRC "com/github/foamdino/Test.java",
	               "-d",
	               BUILD_FOLDER);
	if (!nob_cmd_run_sync(javac_cmd))
		return 1;

	/* compile tests */

	nob_cmd_append(&test_cmd,
	               "cc",
	               "-Wall",
	               "-Wextra",
	               "-fPIC",
	               JAVA_INC,
	               LINUX_INC,
	               "-I.",
	               "-g",
	               "-o",
	               BUILD_FOLDER "test_cooper");
	add_sources_from_dir(&test_cmd, LIB_FOLDER);
	add_sources_from_dir(&test_cmd, AGENT_FOLDER);
	// add_sources_from_dir(&test_cmd, SRC_FOLDER);
	nob_cmd_append(&test_cmd, SRC_FOLDER "test/test_cooper.c");
	nob_cmd_append(&test_cmd, "-pthread", "-lrt");

	if (!nob_cmd_run_sync(test_cmd))
		return 1;

	/* compile tui lib */
	nob_cmd_append(&tui_cmd,
	               "cc",
	               "-Wall",
	               "-Wextra",
	               "-shared",
	               "-fPIC",
	               "-o",
	               BUILD_FOLDER "libtui.so",
	               SRC_FOLDER "tui/tui.c");
	if (!nob_cmd_run_sync(tui_cmd))
		return 1;

	/* compile cli */
	nob_cmd_append(&cli_cmd,
	               "cc",
	               "-Wall",
	               "-Wextra",
	               "-fPIC",
	               LINUX_INC,
	               "-I.",
	               "-Isrc",
	               "-g",
	               "-o",
	               BUILD_FOLDER "cli",
	               SRC_FOLDER "tui/tui_loader.c",
	               SRC_FOLDER "cli/cli.c",
	               "-lrt",
	               "-ldl");

	if (!nob_cmd_run_sync(cli_cmd))
		return 1;

	/* compile test_bytecode.c */
	nob_cmd_append(&test_bytecode_cmd,
	               "cc",
	               "-Wall",
	               "-Wextra",
	               "-fPIC",
	               JAVA_INC,
	               LINUX_INC,
	               "-I.",
	               "-g",
	               "-o",
	               BUILD_FOLDER "test_bytecode");
	add_sources_from_dir(&test_bytecode_cmd, LIB_FOLDER);
	nob_cmd_append(
	    &test_bytecode_cmd, SRC_FOLDER "test/test_bytecode.c", "-pthread", "-lrt");
	if (!nob_cmd_run_sync(test_bytecode_cmd))
		return 1;

	// Generate compile_commands.json
	FILE *cc_json = fopen("compile_commands.json", "w");
	if (cc_json)
	{
		fprintf(cc_json, "[\n");
		bool first = true;
		gen_compile_commands_for_cmd(cc_cmd, cc_json, &first);
		gen_compile_commands_for_cmd(test_cmd, cc_json, &first);
		gen_compile_commands_for_cmd(tui_cmd, cc_json, &first);
		gen_compile_commands_for_cmd(cli_cmd, cc_json, &first);
		gen_compile_commands_for_cmd(test_bytecode_cmd, cc_json, &first);
		fprintf(cc_json, "\n]");
		fclose(cc_json);
		nob_log(NOB_INFO, "Generated compile_commands.json");
	}
	else
	{
		nob_log(NOB_ERROR, "Failed to open compile_commands.json for writing");
	}

	return 0;
}