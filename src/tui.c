/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tui.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UI_VERSION "1.0.0"

static char frame_buffer[4096];
static size_t buffer_pos = 0;

static void reset_frame_buffer(void)
{
    buffer_pos = 0;
}

/* Append string to frame buffer with bounds checking */
static void append_to_buffer(const char* str) 
{
    size_t len = strlen(str);
    size_t remaining = sizeof(frame_buffer) - buffer_pos - 1; /* Reserve null terminator */
    
    if (len > remaining)
        len = remaining;
    
    memcpy(frame_buffer + buffer_pos, str, len);
    buffer_pos += len;
}

/* Append formatted string to buffer */
static void append_formatted(const char* format, ...) 
{
    char temp_buffer[512];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(temp_buffer, sizeof(temp_buffer), format, args);
    va_end(args);
    
    if (len > 0 && len < (int)sizeof(temp_buffer))
        append_to_buffer(temp_buffer);
}

/* Flush buffer to terminal in single write */
static void flush_frame_buffer(void) 
{
    if (buffer_pos > 0) 
    {
        frame_buffer[buffer_pos] = '\0';
        write(STDOUT_FILENO, frame_buffer, buffer_pos);
    }
}

// /* Modify the printf functions to track lines */
// void tui_safe_print(tui_terminal_info_t *terminal, const char *format, ...) 
// {
//     if (terminal->lines_drawn >= terminal->height - 1) 
//         return; /* Don't exceed terminal height */
    
//     char line_buffer[1024]; /* Adjust size as needed */
//     va_list args;
//     va_start(args, format);
//     vsnprintf(line_buffer, sizeof(line_buffer), format, args);
//     va_end(args);
    
//     printf("%s", line_buffer);
    
//     /* Count newlines in the format string */
//     for (const char *p = format; *p; p++) {
//         if (*p == '\n') 
//             terminal->lines_drawn++;
//     }
// }

// void tui_build_line(char *buffer, size_t buffer_size, int width, const char *format, ...)
// {
//     char content[512]; /* Temporary buffer for formatted content */
//     va_list args;
//     int content_len;
//     int padding_needed;
    
//     /* Format the content string */
//     va_start(args, format);
//     content_len = vsnprintf(content, sizeof(content), format, args);
//     va_end(args);
    
//     /* Handle formatting errors or truncation */
//     if (content_len < 0) 
//     {
//         content[0] = '\0';
//         content_len = 0;
//     } 
//     else if (content_len >= (int)sizeof(content)) 
//     {
//         content_len = sizeof(content) - 1;
//     }
    
//     padding_needed = width - content_len - 2; /* Account for │ + │ */
//     if (padding_needed < 0) 
//         padding_needed = 0;
    
//     snprintf(buffer, buffer_size, "│%s%*s│\n", content, padding_needed, "");
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
    reset_frame_buffer();
    append_to_buffer("\033[2J\033[H");
}

// /* Function to clear screen and reset line counter */
// void tui_clear_screen_safe(tui_terminal_info_t *terminal)
// {
//     printf("\033[2J\033[H");
//     terminal->lines_drawn = 0; /* Reset line counter */
// }

// void tui_draw_header(tui_context_t *ctx)
// {
//     tui_terminal_info_t *term = (tui_terminal_info_t*)&ctx->terminal;
//     char* view_names[] = {"Overview", "Methods", "Memory", "Objects"};
//     char title[256];
//     char line[256];
//     snprintf(title, sizeof(title), " Cooper Monitor - %s ", view_names[ctx->current_view]);
//     int title_len = strlen(title);
//     int padding = (ctx->terminal.width - title_len) / 2;

//     tui_safe_print(term, "┌");
//     for (int i = 0; i < ctx->terminal.width - 2; i++) tui_safe_print(term, "─");
//     tui_safe_print(term, "┐\n");

//     tui_safe_print(term, "│");
//     for (int i = 0; i < padding; i++) tui_safe_print(term," ");
//     tui_safe_print(term, "%s", title);
//     for (int i = padding + title_len; i < ctx->terminal.width -2; i++) tui_safe_print(term, " ");
//     tui_safe_print(term, "│\n");

//     tui_safe_print(term, "├");
//     for (int i = 0; i < ctx->terminal.width - 2; i++) tui_safe_print(term, "─");
//     tui_safe_print(term, "┤\n");

//     tui_build_line(line, sizeof(line), ctx->terminal.width, " Keys: [1-4] Switch views  [q] Quit");

//     tui_safe_print(term, "%s", line);

//     tui_safe_print(term, "├");
//     for (int i = 0; i < ctx->terminal.width - 2; i++) tui_safe_print(term, "─");
//     tui_safe_print(term, "┤\n");
// }

void tui_draw_header(tui_context_t *ctx) 
{
    char* view_names[] = {"Overview", "Methods", "Memory", "Objects"};
    
    append_formatted("Cooper Monitor - %s\n", view_names[ctx->current_view]);
    
    /* Separator line */
    for (int i = 0; i < ctx->terminal.width; i++) 
    {
        append_to_buffer("─");
    }
    append_to_buffer("\n");
    
    append_to_buffer("Keys: [1-4] Switch views  [q] Quit\n\n");
}

void tui_draw_bar_chart(tui_context_t *ctx, char *title, const char *items[], uint64_t values[], int count, uint64_t max_val, int term_width)
{
    append_formatted("%s\n", title);
    append_to_buffer("\n");
    int max_name_len = 25;
    int bar_width = term_width - max_name_len - 15; /* Leave space for value and borders */

    if (bar_width < 10) bar_width = 10;

    for (int i = 0; i < count && i < term_width - 10; i++) 
    {
        append_formatted("%-*.*s", max_name_len, max_name_len, items[i]);
        
        int bar_len = max_val > 0 ? (values[i] * bar_width) / max_val : 0;
        if (bar_len > bar_width) bar_len = bar_width;
        
        append_to_buffer("[");
        for (int j = 0; j < bar_len; j++) append_to_buffer("█");
        for (int j = bar_len; j < bar_width; j++) append_to_buffer(" ");
        append_formatted("] %8lu\n", (unsigned long)values[i]);
    }
}

void tui_draw_memory_history(tui_context_t *ctx, const tui_memory_display_t *memory_data, int term_width)
{
    append_to_buffer("Process Memory History (MB)\n");
    if (memory_data->history_count < 2) 
    {
        append_to_buffer("Collecting data...\n");
        return;
    }

    /* Find min/max for scaling */
    uint64_t min_mem = memory_data->memory_history[0];
    uint64_t max_mem = memory_data->memory_history[0];

    for (int i = 1; i < memory_data->history_count; i++) 
    {
        if (memory_data->memory_history[i] < min_mem) min_mem = memory_data->memory_history[i];
        if (memory_data->memory_history[i] > max_mem) max_mem = memory_data->memory_history[i];
    }

    int chart_height = 8;
    int chart_width = term_width - 4;

    /* Draw the chart from top to bottom */
    for (int row = 0; row < chart_height; row++) 
    {
        char chart_line[256];
    
        /* Initialize with just a space */
        chart_line[0] = '\0';  /* Null terminate for strcat */
        strcat(chart_line, " ");
        
        uint64_t threshold = max_mem - ((max_mem - min_mem) * row) / chart_height;
        
        for (int col = 0; col < chart_width; col++) {
            if (col < memory_data->history_count) {
                if (memory_data->memory_history[col] >= threshold) {
                    strcat(chart_line, "█");
                } else {
                    strcat(chart_line, " ");
                }
            } else {
                /* Fill remaining space with spaces */
                strcat(chart_line, " ");
            }
        }
        
        /* Use "%s" format and pass chart_line as argument */
        append_formatted("%s", chart_line);
    }

    append_formatted("Min: %lu MB  Max: %lu MB  Current: %lu MB\n", 
        (unsigned long)(min_mem / 1024 / 1024),
        (unsigned long)(max_mem / 1024 / 1024),
        (unsigned long)(memory_data->process_memory / 1024 / 1024));
}

void tui_draw_histogram(tui_context_t *ctx, char *title, uint64_t values[], int count, int term_width)
{
    append_formatted("%s\n", title);
    append_to_buffer("\n");
    if (count == 0) 
    {
        append_to_buffer("No data available\n");
        return;
    }

    /* Create histogram buckets */
    uint64_t min_val = values[0];
    uint64_t max_val = values[0];

    for (int i = 1; i < count; i++) {
        if (values[i] < min_val) min_val = values[i];
        if (values[i] > max_val) max_val = values[i];
    }

    if (max_val == min_val) 
    {
        append_formatted("All values are identical: %lu\n", (unsigned long)min_val);
        return;
    }

    int num_buckets = 20;
    int buckets[20] = {0};
    uint64_t bucket_size = (max_val - min_val) / num_buckets;

    for (int i = 0; i < count; i++) 
    {
        int bucket = (values[i] - min_val) / bucket_size;
        if (bucket >= num_buckets) bucket = num_buckets - 1;
        buckets[bucket]++;
    }

    /* Find max bucket count for scaling */
    int max_bucket = 0;
    for (int i = 0; i < num_buckets; i++) 
    {
        if (buckets[i] > max_bucket) 
            max_bucket = buckets[i];
    }

    /* Draw histogram */
    int bar_height = 6;
    for (int row = bar_height; row > 0; row--) 
    {
        for (int col = 0; col < num_buckets; col++) {
            int height = max_bucket > 0 ? (buckets[col] * bar_height) / max_bucket : 0;
            if (height >= row) {
                append_to_buffer("█");
            } else {
                append_to_buffer(" ");
            }
        }
        append_to_buffer("\n");
    }
}

void tui_draw_overview(tui_context_t *ctx)
{
    append_to_buffer("System Overview\n\n");
    
    append_formatted("Process Memory: %lu MB\n", 
        (unsigned long)(ctx->memory_data->process_memory / 1024 / 1024));
    append_formatted("Active Threads: %d\n", ctx->memory_data->active_threads);
    append_formatted("Tracked Methods: %d\n", ctx->method_count);
    append_formatted("Object Types: %d\n\n", ctx->object_count);
    
    if (ctx->method_count > 0) 
    {
        append_to_buffer("Top Methods by Calls:\n");
        for (int i = 0; i < ctx->method_count && i < 5; i++) 
        {
            const char* last_slash = strrchr(ctx->methods[i].signature, '/');
            const char* display_name = last_slash ? last_slash + 1 : ctx->methods[i].signature;
            
            append_formatted("  %.45s %8lu calls\n", 
                display_name, (unsigned long)ctx->methods[i].call_count);
        }
    }
}

void tui_draw_methods_view(tui_context_t *ctx)
{   
    if (ctx->method_count == 0) 
    {
        append_to_buffer("No method data available\n");
        return;
    }
    /* Show methods by average execution time */
    const char* method_names[UI_MAX_DISPLAY_ITEMS];
    uint64_t avg_times[UI_MAX_DISPLAY_ITEMS];
    uint64_t max_time = 0;

    for (int i = 0; i < ctx->method_count; i++) 
    {
        const char* last_slash = strrchr(ctx->methods[i].signature, '/');
        method_names[i] = last_slash ? last_slash + 1 : ctx->methods[i].signature;
        avg_times[i] = ctx->methods[i].avg_time_ns / 1000; /* Convert to microseconds */
        if (avg_times[i] > max_time) 
            max_time = avg_times[i];
    }

    tui_draw_bar_chart(ctx, "Method Execution Times (μs)", method_names, avg_times, 
                    ctx->method_count, max_time, ctx->terminal.width);
}

void tui_draw_memory_view(tui_context_t *ctx)
{
    tui_draw_memory_history(ctx, ctx->memory_data, ctx->terminal.width);
    append_to_buffer("\n");

    if (ctx->memory_data->active_threads > 0) 
    {
        append_to_buffer("Thread Memory Usage (MB):\n");
        for (int i = 0; i < ctx->memory_data->active_threads; i++) 
        {
            
            append_formatted("Thread %lu: %lu MB\n", 
                (unsigned long)ctx->memory_data->thread_ids[i],
                (unsigned long)(ctx->memory_data->thread_memory[i] / 1024 / 1024));
        }
    }
}

void tui_draw_objects_view(tui_context_t *ctx)
{
    if (ctx->object_count == 0) 
    {
        append_to_buffer("No object allocation data available\n");
        return;
    }

    /* Show objects by total bytes allocated */
    const char* object_names[UI_MAX_DISPLAY_ITEMS];
    uint64_t bytes_allocated[UI_MAX_DISPLAY_ITEMS];
    uint64_t max_bytes = 0;

    for (int i = 0; i < ctx->object_count; i++) 
    {
        const char* last_slash = strrchr(ctx->objects[i].class_name, '/');
        object_names[i] = last_slash ? last_slash + 1 : ctx->objects[i].class_name;
        bytes_allocated[i] = ctx->objects[i].total_bytes;
        if (bytes_allocated[i] > max_bytes) max_bytes = bytes_allocated[i];
    }

    tui_draw_bar_chart(ctx, "Object Allocations (bytes)", object_names, bytes_allocated, 
                    ctx->object_count, max_bytes, ctx->terminal.width);
}

void tui_draw_footer(tui_context_t *ctx)
{
    /* Separator line */
    for (int i = 0; i < ctx->terminal.width; i++) 
    {
        append_to_buffer("─");
    }
    append_to_buffer("\n");
    append_to_buffer("\nPress 'q' to quit\n");
}

void tui_draw(tui_context_t *ctx)
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
    
    tui_draw_footer(ctx);
    flush_frame_buffer();
}