/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tui.h"
#include <stdio.h>
#include <string.h>

#define UI_VERSION "1.0.0"

/* Modify the printf functions to track lines */
// static void safe_printf(const char *format, ...) 
// {
//     if (lines_drawn >= term_height - 1) return; /* Don't exceed terminal height */
    
//     va_list args;
//     va_start(args, format);
//     vprintf(format, args);
//     va_end(args);
    
//     /* Count newlines in the format string */
//     for (const char *p = format; *p; p++) {
//         if (*p == '\n') lines_drawn++;
//     }
// }

int tui_init(void)
{
    /* Initialize any UI library state if needed */
    return 0;
}

void tui_cleanup(void)
{
    /* Cleanup any UI library resources */
}

char* tui_get_version(void)
{
    return UI_VERSION;
}

void tui_clear_screen(void)
{
    printf("\033[2J\033[H");
}

void tui_draw_header(const tui_context_t *ctx)
{
    const char view_names[] = {"Overview", "Methods", "Memory", "Objects"};
    char title[256];
    snprintf(title, sizeof(title), " Cooper Monitor - %s ", view_names[ctx->current_view]);
    int title_len = strlen(title);
    int padding = (ctx->terminal.width - title_len) / 2;

    printf("┌");
    for (int i = 0; i < ctx->terminal.width - 2; i++) printf("─");
    printf("┐\n");

    printf("│");
    for (int i = 0; i < padding; i++) printf(" ");
    printf("%s", title);
    for (int i = padding + title_len; i < ctx->terminal.width - 1; i++) printf(" ");
    printf("│\n");

    printf("├");
    for (int i = 0; i < ctx->terminal.width - 2; i++) printf("─");
    printf("┤\n");

    printf("│ Keys: [1-4] Switch views  [q] Quit");
    for (int i = 34; i < ctx->terminal.width - 1; i++) printf(" ");
    printf("│\n");

    printf("├");
    for (int i = 0; i < ctx->terminal.width - 2; i++) printf("─");
    printf("┤\n");
}

void tui_draw_bar_chart(const char* title, const char* items[], uint64_t values[], int count, uint64_t max_val, int term_width)
{
    printf("│ %s\n", title);
    printf("│\n");
    int max_name_len = 25;
    int bar_width = term_width - max_name_len - 15; /* Leave space for value and borders */

    if (bar_width < 10) bar_width = 10;

    for (int i = 0; i < count && i < term_width - 10; i++) {
        printf("│ %-*.*s", max_name_len, max_name_len, items[i]);
        
        int bar_len = max_val > 0 ? (values[i] * bar_width) / max_val : 0;
        if (bar_len > bar_width) bar_len = bar_width;
        
        printf(" [");
        for (int j = 0; j < bar_len; j++) printf("█");
        for (int j = bar_len; j < bar_width; j++) printf(" ");
        printf("] %8lu\n", (unsigned long)values[i]);
    }
}

void tui_draw_memory_history(const tui_memory_display_t *memory_data, int term_width)
{
    printf("│ Process Memory History (MB)\n");
    printf("│\n");
    if (memory_data->history_count < 2) {
        printf("│ Collecting data...\n");
        return;
    }

    /* Find min/max for scaling */
    uint64_t min_mem = memory_data->memory_history[0];
    uint64_t max_mem = memory_data->memory_history[0];

    for (int i = 1; i < memory_data->history_count; i++) {
        if (memory_data->memory_history[i] < min_mem) min_mem = memory_data->memory_history[i];
        if (memory_data->memory_history[i] > max_mem) max_mem = memory_data->memory_history[i];
    }

    int chart_height = 8;
    int chart_width = term_width - 10;

    /* Draw the chart from top to bottom */
    for (int row = 0; row < chart_height; row++) {
        printf("│ ");
        uint64_t threshold = max_mem - ((max_mem - min_mem) * row) / chart_height;
        
        for (int col = 0; col < memory_data->history_count && col < chart_width; col++) {
            if (memory_data->memory_history[col] >= threshold) {
                printf("█");
            } else {
                printf(" ");
            }
        }
        printf("\n");
    }

    printf("│ Min: %lu MB  Max: %lu MB  Current: %lu MB\n", 
        (unsigned long)(min_mem / 1024 / 1024),
        (unsigned long)(max_mem / 1024 / 1024),
        (unsigned long)(memory_data->process_memory / 1024 / 1024));
}

void tui_draw_histogram(const char* title, uint64_t values[], int count, int term_width)
{
    printf("│ %s\n", title);
    printf("│\n");
    if (count == 0) {
        printf("│ No data available\n");
        return;
    }

    /* Create histogram buckets */
    uint64_t min_val = values[0];
    uint64_t max_val = values[0];

    for (int i = 1; i < count; i++) {
        if (values[i] < min_val) min_val = values[i];
        if (values[i] > max_val) max_val = values[i];
    }

    if (max_val == min_val) {
        printf("│ All values are identical: %lu\n", (unsigned long)min_val);
        return;
    }

    int num_buckets = 20;
    int buckets[20] = {0};
    uint64_t bucket_size = (max_val - min_val) / num_buckets;

    for (int i = 0; i < count; i++) {
        int bucket = (values[i] - min_val) / bucket_size;
        if (bucket >= num_buckets) bucket = num_buckets - 1;
        buckets[bucket]++;
    }

    /* Find max bucket count for scaling */
    int max_bucket = 0;
    for (int i = 0; i < num_buckets; i++) {
        if (buckets[i] > max_bucket) max_bucket = buckets[i];
    }

    /* Draw histogram */
    int bar_height = 6;
    for (int row = bar_height; row > 0; row--) {
        printf("│ ");
        for (int col = 0; col < num_buckets; col++) {
            int height = max_bucket > 0 ? (buckets[col] * bar_height) / max_bucket : 0;
            if (height >= row) {
                printf("█");
            } else {
                printf(" ");
            }
        }
        printf("\n");
    }
}

void tui_draw_overview(const tui_context_t *ctx)
{
    printf("│ System Overview\n");
    printf("│\n");
    printf("│ Process Memory: %lu MB\n", (unsigned long)(ctx->memory_data->process_memory / 1024 / 1024));
    printf("│ Active Threads: %d\n", ctx->memory_data->active_threads);
    printf("│ Tracked Methods: %d\n", ctx->method_count);
    printf("│ Object Types: %d\n", ctx->object_count);
    printf("│\n");

    /* Show top methods by call count */
    if (ctx->method_count > 0) {
        printf("│ Top Methods by Calls:\n");
        for (int i = 0; i < ctx->method_count && i < 5; i++) {
            char short_name[50];
            const char* last_slash = strrchr(ctx->methods[i].signature, '/');
            const char* display_name = last_slash ? last_slash + 1 : ctx->methods[i].signature;
            snprintf(short_name, sizeof(short_name), "%.45s", display_name);
            
            printf("│   %-45s %8lu calls\n", short_name, (unsigned long)ctx->methods[i].call_count);
        }
    }
}

void tui_draw_methods_view(const tui_context_t *ctx)
{
    if (ctx->method_count == 0) {
        printf("│ No method data available\n");
        return;
    }
    /* Show methods by average execution time */
    const char* method_names[UI_MAX_DISPLAY_ITEMS];
    uint64_t avg_times[UI_MAX_DISPLAY_ITEMS];
    uint64_t max_time = 0;

    for (int i = 0; i < ctx->method_count; i++) {
        const char* last_slash = strrchr(ctx->methods[i].signature, '/');
        method_names[i] = last_slash ? last_slash + 1 : ctx->methods[i].signature;
        avg_times[i] = ctx->methods[i].avg_time_ns / 1000; /* Convert to microseconds */
        if (avg_times[i] > max_time) max_time = avg_times[i];
    }

    tui_draw_bar_chart("Method Execution Times (μs)", method_names, avg_times, 
                    ctx->method_count, max_time, ctx->terminal.width);
}

void tui_draw_memory_view(const tui_context_t *ctx)
{
    tui_draw_memory_history(ctx->memory_data, ctx->terminal.width);
    printf("│\n");

    if (ctx->memory_data->active_threads > 0) {
        printf("│ Thread Memory Usage (MB):\n");
        for (int i = 0; i < ctx->memory_data->active_threads; i++) {
            printf("│ Thread %lu: %lu MB\n", 
                (unsigned long)ctx->memory_data->thread_ids[i],
                (unsigned long)(ctx->memory_data->thread_memory[i] / 1024 / 1024));
        }
    }
}

void tui_draw_objects_view(const tui_context_t *ctx)
{
    if (ctx->object_count == 0) {
        printf("│ No object allocation data available\n");
        return;
    }

    /* Show objects by total bytes allocated */
    const char* object_names[UI_MAX_DISPLAY_ITEMS];
    uint64_t bytes_allocated[UI_MAX_DISPLAY_ITEMS];
    uint64_t max_bytes = 0;

    for (int i = 0; i < ctx->object_count; i++) {
        const char* last_slash = strrchr(ctx->objects[i].class_name, '/');
        object_names[i] = last_slash ? last_slash + 1 : ctx->objects[i].class_name;
        bytes_allocated[i] = ctx->objects[i].total_bytes;
        if (bytes_allocated[i] > max_bytes) max_bytes = bytes_allocated[i];
    }

    tui_draw_bar_chart("Object Allocations (bytes)", object_names, bytes_allocated, 
                    ctx->object_count, max_bytes, ctx->terminal.width);
}

void tui_draw_footer(const tui_context_t *ctx)
{
    printf("└");
    for (int i = 0; i < ctx->terminal.width - 2; i++) printf("─");
    printf("┘\n");
}

void tui_draw(const tui_context_t *ctx)
{
    tui_clear_screen();
    tui_draw_header(ctx);
    switch (ctx->current_view) {
        case UI_VIEW_OVERVIEW:
            tui_draw_overview(ctx);
            break;
        case UI_VIEW_METHODS:
            tui_draw_methods_view(ctx);
            break;
        case UI_VIEW_MEMORY:
            tui_draw_memory_view(ctx);
            break;
        case UI_VIEW_OBJECTS:
            tui_draw_objects_view(ctx);
            break;
        default:
            break;
    }

    /* Fill remaining space */
    int lines_used = 8; /* Header + footer estimate */
    for (int i = lines_used; i < ctx->terminal.height - 1; i++) {
        printf("│");
        for (int j = 0; j < ctx->terminal.width - 2; j++) printf(" ");
        printf("│\n");
    }

    tui_draw_footer(ctx);
    fflush(stdout);
}