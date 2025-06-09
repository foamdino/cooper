/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// This is your build script. You only need to "bootstrap" it once with `cc -o nob nob.c` (you can
// call it whatever actually) or `cl nob.c` on MSVC and thanks to NOB_GO_REBUILD_URSELF (see below).
// After that every time you run the `nob` executable if it detects that you modifed nob.c it will
// rebuild itself automatically

// nob.h is an stb-style library https://github.com/nothings/stb/blob/master/docs/stb_howto.txt
// What that means is that it's a single file that acts both like .c and .h files, but by default
// when you include it, it acts only as .h. To make it include implementations of the functions
// you must define NOB_IMPLEMENTATION macro. This is done to give you full control over where
// the implementations go.
#define NOB_IMPLEMENTATION

// Always keep a copy of nob.h in your repo. One of my main pet peeves with build systems like CMake
// and Autotools is that the codebases that use them naturally rot. That is if you do not actively update
// your build scripts, they may not work with the latest version of the build tools. Here we basically
// include the entirety of the source code of the tool along with the code base. It will never get
// outdated.
//
// (In these examples we actually symlinking nob.h, but this is to keep nob.h-s synced among all the
// examples)
#include "nob.h"

#include <stdlib.h>
// TODO: add more comments in here

#define BUILD_FOLDER "build/"
#define SRC_FOLDER   "src/"

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);

    Nob_Cmd cc_cmd = {0};
    Nob_Cmd javac_cmd = {0};
    Nob_Cmd test_cmd = {0};

    const char *JAVA_HOME = getenv("JAVA_HOME");
    assert(JAVA_HOME != NULL);

    int j_buf_sz = strlen(JAVA_HOME) + strlen("/include") +3;
    char JAVA_INC[j_buf_sz];
    snprintf(JAVA_INC, j_buf_sz, "-I%s/%s", JAVA_HOME, "include");
    
    int l_buf_sz = strlen(JAVA_HOME) + strlen("/include") + strlen("/linux") +3;
    char LINUX_INC[l_buf_sz];
    snprintf(LINUX_INC, l_buf_sz, "-I%s/%s/%s", JAVA_HOME, "include", "linux");

    /* Check that the build output dir exists */
    if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;

    // Check for debug build
    int debug_build = 0;
    for (int i=1; i<argc; i++)
    {
        if (strcmp(argv[i], "--debug") == 0)
        {
            debug_build = 1;
            break;
        }
    }

    nob_cmd_append(&cc_cmd, "cc", "-Wall", "-Wextra", "-shared", "-fPIC",
                   JAVA_INC, LINUX_INC, "-I.");

    if (debug_build)
    {
        nob_cmd_append(&cc_cmd, "-DENABLE_DEBUG_LOGS", "-DENABLE_INFO_LOGS", "-g");
        printf("Building in DEBUG mode with logs enabled\n");
    }
    else
        nob_cmd_append(&cc_cmd, "-DENABLE_INFO_LOGS", "-O2");

    nob_cmd_append(&cc_cmd, "-o", BUILD_FOLDER"libcooper.so", 
        SRC_FOLDER"arena.c", SRC_FOLDER"arena_str.c", SRC_FOLDER"log.c", SRC_FOLDER"cache.c", SRC_FOLDER"config.c", SRC_FOLDER"shared_mem.c", SRC_FOLDER"thread_util.c", SRC_FOLDER"cooper.c", SRC_FOLDER"cli.c", "-pthread", "-lrt");

    if (!nob_cmd_run_sync(cc_cmd)) return 1;

    /* compile java */
    nob_cmd_append(&javac_cmd, "javac", "java-src/com/github/foamdino/Test.java", "-d", BUILD_FOLDER);
    if (!nob_cmd_run_sync(javac_cmd)) return 1;

    /* compile tests */
    
    nob_cmd_append(&test_cmd, "cc", "-Wall", "-Wextra", "-fPIC", JAVA_INC, LINUX_INC, "-I.", "-Isrc", "-g", "-o", BUILD_FOLDER"test_cooper", 
        SRC_FOLDER"arena.c", SRC_FOLDER"arena_str.c", SRC_FOLDER"log.c", SRC_FOLDER"cache.c", SRC_FOLDER"config.c", SRC_FOLDER"shared_mem.c", SRC_FOLDER"thread_util.c", SRC_FOLDER"cooper.c", SRC_FOLDER"test_cooper.c", "-pthread", "-lrt");
    
    if (!nob_cmd_run_sync(test_cmd)) return 1;

    return 0;
}