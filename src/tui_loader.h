/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef UI_LOADER_H
#define UI_LOADER_H

#include <time.h>

#include "tui.h"

typedef struct tui_loader tui_loader_t;

struct tui_loader
{
    char *library_path;
    void *handle;
    time_t last_mod_time;
    /* Function pointers to UI library functions */
    int (*tui_init)(void);
    void (*tui_cleanup)(void);
    char *(*tui_get_version)(void);
    void (*tui_draw)(const tui_context_t *ctx);
    void (*tui_clear_screen)(void);
};

/**
 * Initialize the UI loader
 * @param ui_library_path Path to the UI shared library
 * @return UI loader instance or NULL on failure
 */
tui_loader_t *tui_loader_init(const char *ui_library_path);

/**
 * Cleanup the UI loader
 * @param loader UI loader instance
 */
void tui_loader_cleanup(tui_loader_t *loader);

/**
 * Check if the UI library has been modified and reload if necessary
 * @param loader UI loader instance
 * @return 0 if no reload needed, 1 if reloaded successfully, -1 on error
 */
int tui_loader_check_and_reload(tui_loader_t *loader);

/**
 * Draw the UI using the loaded library
 * @param loader UI loader instance
 * @param ctx UI context
 */
void tui_loader_draw(tui_loader_t *loader, const tui_context_t *ctx);

/**
 * Get the version of the loaded UI library
 * @param loader UI loader instance
 * @return Version string or NULL if not loaded
 */
char* tui_loader_get_version(tui_loader_t *loader);

/**
 * Check if the UI library is currently loaded
 * @param loader UI loader instance
 * @return 1 if loaded, 0 if not
 */
int tui_loader_is_loaded(tui_loader_t *loader);

#endif /* UI_LOADER_H */