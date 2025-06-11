/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TUI_H
#define TUI_H

#include <stdint.h>
#include <time.h>

#define UI_MAX_DISPLAY_ITEMS 20
#define UI_MAX_HISTORY_POINTS 100
#define UI_MAX_SIGNATURE_LEN 512

typedef enum {
    UI_VIEW_OVERVIEW = 0,
    UI_VIEW_METHODS = 1,
    UI_VIEW_MEMORY = 2,
    UI_VIEW_OBJECTS = 3,
    UI_VIEW_COUNT
} ui_view_mode_e;

#endif /* TUI_H */