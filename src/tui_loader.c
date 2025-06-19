/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tui_loader.h"
#include <dlfcn.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



static time_t get_file_mod_time(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return st.st_mtime;

    return 0;
}

static int load_tui_functions(tui_loader_t *loader)
{
    /* Load all UI function pointers */
    loader->tui_init = dlsym(loader->handle, "tui_init");
    loader->tui_cleanup = dlsym(loader->handle, "tui_cleanup");
    loader->tui_get_version = dlsym(loader->handle, "tui_get_version");
    loader->tui_draw = dlsym(loader->handle, "tui_draw");
    loader->tui_clear_screen = dlsym(loader->handle, "tui_clear_screen");
    /* Check if all functions were loaded */
    if (!loader->tui_init || !loader->tui_cleanup || !loader->tui_get_version || 
        !loader->tui_draw || !loader->tui_clear_screen) {
        fprintf(stderr, "Failed to load TUI library functions: %s\n", dlerror());
        return -1;
    }

    /* Initialize the UI library */
    if (loader->tui_init() != 0) {
        fprintf(stderr, "Failed to initialize TUI library\n");
        return -1;
    }

    return 0;
}

static int load_tui_library(tui_loader_t *loader)
{
    /* Close existing handle if open */
    if (loader->handle) {
        if (loader->tui_cleanup)
            loader->tui_cleanup();
        
        dlclose(loader->handle);
        loader->handle = NULL;
    }

    /* Load the new library */
    loader->handle = dlopen(loader->library_path, RTLD_NOW);
    if (!loader->handle) {
        fprintf(stderr, "Failed to load TUI library: %s\n", dlerror());
        return -1;
    }

    /* Load function pointers */
    if (load_tui_functions(loader) != 0) {
        dlclose(loader->handle);
        loader->handle = NULL;
        return -1;
    }

    /* Update modification time */
    loader->last_mod_time = get_file_mod_time(loader->library_path);

    printf("TUI library loaded successfully (version: %s)\n", 
        loader->tui_get_version ? loader->tui_get_version() : "unknown");

    return 0;
}

tui_loader_t *tui_loader_init(const char *tui_library_path)
{
    if (!tui_library_path)
        return NULL;
    
    tui_loader_t *loader = calloc(1, sizeof(tui_loader_t));
    if (!loader)
        return NULL;

    loader->library_path = strdup(tui_library_path);
    if (!loader->library_path) {
        free(loader);
        return NULL;
    }

    /* Try to load the initial library */
    if (load_tui_library(loader) != 0) {
        free(loader->library_path);
        free(loader);
        return NULL;
    }

    return loader;
}

void tui_loader_cleanup(tui_loader_t *loader)
{
    if (!loader) 
        return;

    if (loader->handle) {
        if (loader->tui_cleanup) {
            loader->tui_cleanup();
        }
        dlclose(loader->handle);
    }

    free(loader->library_path);
    free(loader);
}

int tui_loader_check_and_reload(tui_loader_t *loader)
{
    if (!loader) 
        return -1;
    
    time_t current_mod_time = get_file_mod_time(loader->library_path);
    /* File doesn't exist or can't be accessed */
    if (current_mod_time == 0)
        return -1;

    if (current_mod_time > loader->last_mod_time) {
        printf("TUI library changed, reloading...\n");
        if (load_tui_library(loader) == 0)
            return 1; /* Reloaded successfully */
        else
            return -1; /* Reload failed */
}

    return 0; /* No reload needed */
}

void tui_loader_draw(tui_loader_t *loader, const tui_context_t *ctx)
{
    if (loader && loader->tui_draw)
        loader->tui_draw(ctx);
}

char* tui_loader_get_version(tui_loader_t *loader)
{
    if (loader && loader->tui_get_version)
        return loader->tui_get_version();

    return NULL;
}

int tui_loader_is_loaded(tui_loader_t *loader)
{
    return loader && loader->handle != NULL;
}