/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TUI_H
#define TUI_H

#include <stdint.h>
#include <time.h>
#include <stdarg.h>

#define UI_MAX_DISPLAY_ITEMS 20
#define UI_MAX_HISTORY_POINTS 100
#define UI_MAX_SIGNATURE_LEN 512

typedef enum tui_view_mode tui_view_mode_e;
typedef struct tui_method_display tui_method_display_t;
typedef struct tui_object_display tui_object_display_t;
typedef struct tui_memory_display tui_memory_display_t;
typedef struct tui_terminal_info tui_terminal_info_t;
typedef struct tui_context tui_context_t;

enum tui_view_mode 
{
    UI_VIEW_OVERVIEW = 0,
    UI_VIEW_METHODS = 1,
    UI_VIEW_MEMORY = 2,
    UI_VIEW_OBJECTS = 3,
    UI_VIEW_COUNT
};

struct tui_method_display 
{
    char signature[UI_MAX_SIGNATURE_LEN];
    uint64_t call_count;
    uint64_t sample_count;
    uint64_t total_time_ns;
    uint64_t min_time_ns;
    uint64_t max_time_ns;
    uint64_t avg_time_ns;
    uint64_t alloc_bytes;
    uint64_t peak_memory;
    uint64_t cpu_cycles;
    time_t last_updated;
};

struct tui_object_display 
{
    char class_name[UI_MAX_SIGNATURE_LEN];
    uint64_t allocation_count;
    uint64_t total_bytes;
    uint64_t current_instances;
    uint64_t peak_instances;
    uint64_t min_size;
    uint64_t max_size;
    uint64_t avg_size;
    time_t last_updated;
};

struct tui_memory_display 
{
    uint64_t process_memory;
    uint64_t thread_memory[10]; /* Track up to 10 threads */
    uint64_t thread_ids[10];
    int active_threads;
    uint64_t memory_history[UI_MAX_HISTORY_POINTS];
    int history_count;
    time_t last_updated;
};

struct tui_terminal_info
{
    int width;
    int height;
    int lines_drawn;
};

struct tui_context 
{
    tui_method_display_t *methods;
    tui_object_display_t *objects;
    tui_memory_display_t *memory_data;
    tui_view_mode_e current_view;
    tui_terminal_info_t terminal;
    int method_count;
    int object_count;
};

/**
 * Initialize the UI library
 * @return 0 on success, non-zero on failure
 */
int tui_init(void);

/**
 * Cleanup the UI library
 */
void tui_cleanup(void);

/**
 * Get the library version string
 * @return Version string
 */
char *tui_get_version(void);

/**
 * Draw the complete UI
 * @param ctx UI context containing all display data
 */
void tui_draw(tui_context_t *ctx);

/**
 *Draw just the header section
 *@param ctx UI context
 */
void tui_draw_header(tui_context_t *ctx);

/**
 * Draw just the footer section
 * @param ctx UI context
 */
void tui_draw_footer(tui_context_t *ctx);

/**
 * Draw the overview view
 * @param ctx UI context
 */
void tui_draw_overview(tui_context_t *ctx);

/**
 * Draw the methods view
 * @param ctx UI context
 */
void tui_draw_methods_view(tui_context_t *ctx);

/**
 * Draw the memory view
 * @param ctx UI context
 */
void tui_draw_memory_view(tui_context_t *ctx);

/**
 * Draw the objects view
 * @param ctx UI context
 */
void tui_draw_objects_view(tui_context_t *ctx);

/**
 * Clear the screen
 */
void tui_clear_screen(void);

/**
 * Safe print that respects terminal boundaries
 * @param terminal Terminal info with line tracking
 * @param format Printf-style format string
 */
void tui_safe_print(tui_terminal_info_t *terminal, const char *format, ...);

/**
 * Build a formatted line with proper padding and borders
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param width Terminal width
 * @param format Printf-style format string
 * @param ... Format arguments
 */
void tui_build_line(char *buffer, size_t buffer_size, int width, const char *format, ...);

/**
 * Draw a bar chart
 * @param title Chart title
 * @param items Array of item names
 * @param values Array of values
 * @param count Number of items
 * @param max_val Maximum value for scaling
 * @param term_width Terminal width
 */
void tui_draw_bar_chart(tui_context_t *ctx, char *title, const char *items[], uint64_t values[], int count, uint64_t max_val, int term_width);

/**
 * Draw memory history chart
 * @param memory_data Memory data structure
 * @param term_width Terminal width
 */
void tui_draw_memory_history(tui_context_t *ctx, const tui_memory_display_t *memory_data, int term_width);

/**
 * Draw a histogram
 * @param title Chart title
 * @param values Array of values
 * @param count Number of values
 * @param term_width Terminal width
 */
void tui_draw_histogram(tui_context_t *ctx, char *title, uint64_t values[], int count, int term_width);

#endif /* TUI_H */