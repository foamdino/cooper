/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <math.h>
#include <stdarg.h>

#include "tui_loader.h"
#include "shared_mem.h"

#define REFRESH_INTERVAL 250000  /* 250ms */

/* Global UI loader */
static tui_loader_t *loader = NULL;

typedef struct {
    cooper_data_shm_t *data_shm;
    cooper_status_shm_t *status_shm;
    int data_fd;
    int status_fd;
} cli_shm_context_t;

static struct termios orig_termios;
static int term_width = 80;
static int term_height = 24;
static int lines_drawn = 0;
static tui_view_mode_e current_view = UI_VIEW_OVERVIEW;
static cli_shm_context_t shm_ctx = {0};

/* Display data structures */
static tui_method_display_t methods[UI_MAX_DISPLAY_ITEMS];
static tui_object_display_t objects[UI_MAX_DISPLAY_ITEMS];
static tui_memory_display_t memory_data = {0};
static int method_count = 0;
static int object_count = 0;

/* Terminal handling functions */
void disable_raw_mode() 
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() 
{
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void get_terminal_size() 
{
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) 
    {
        term_width = w.ws_col;
        term_height = w.ws_row;
    }
}

void handle_sigwinch(int sig) 
{
    (void)sig;
    get_terminal_size();
}

void handle_sigint(int sig) 
{
    (void)sig;
    disable_raw_mode();
    printf("\033[2J\033[H");
    exit(0);
}

void clear_screen() 
{
    printf("\033[2J\033[H");
}

int kbhit() {
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
}

char getch() 
{
    char c;
    if (read(STDIN_FILENO, &c, 1) == -1) return 0;
    return c;
}

/* Shared memory functions */
int init_cli_shm() 
{
    shm_ctx.data_fd = shm_open(COOPER_DATA_SHM_NAME, O_RDONLY, 0);
    if (shm_ctx.data_fd == -1) {
        return -1;
    }
    
    shm_ctx.status_fd = shm_open(COOPER_STATUS_SHM_NAME, O_RDWR, 0);
    if (shm_ctx.status_fd == -1) {
        close(shm_ctx.data_fd);
        return -1;
    }
    
    shm_ctx.data_shm = mmap(NULL, sizeof(cooper_data_shm_t), PROT_READ, 
                           MAP_SHARED, shm_ctx.data_fd, 0);
    if (shm_ctx.data_shm == MAP_FAILED) {
        close(shm_ctx.data_fd);
        close(shm_ctx.status_fd);
        return -1;
    }
    
    shm_ctx.status_shm = mmap(NULL, sizeof(cooper_status_shm_t), PROT_READ | PROT_WRITE, 
                             MAP_SHARED, shm_ctx.status_fd, 0);
    if (shm_ctx.status_shm == MAP_FAILED) {
        munmap(shm_ctx.data_shm, sizeof(cooper_data_shm_t));
        close(shm_ctx.data_fd);
        close(shm_ctx.status_fd);
        return -1;
    }
    
    return 0;
}

void cleanup_cli_shm() 
{
    if (shm_ctx.data_shm && shm_ctx.data_shm != MAP_FAILED)
        munmap(shm_ctx.data_shm, sizeof(cooper_data_shm_t));
    
    if (shm_ctx.status_shm && shm_ctx.status_shm != MAP_FAILED)
        munmap(shm_ctx.status_shm, sizeof(cooper_status_shm_t));
    
    if (shm_ctx.data_fd > 0) 
        close(shm_ctx.data_fd);

    if (shm_ctx.status_fd > 0) 
        close(shm_ctx.status_fd);
}

/* Data reading and processing functions */
void read_shared_memory_data() 
{
    time_t current_time = time(NULL);
    
    for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++) {
        if (shm_ctx.status_shm->status[i] != ENTRY_READY) continue;
        
        cooper_sample_entry_t *entry = &shm_ctx.data_shm->entries[i];
        
        switch (entry->type) {
            case COOPER_DATA_METHOD_METRIC: {
                /* Clean, semantic access to method data */
                cooper_method_data_t *method = &entry->data.method;
                
                /* Find or create method entry */
                int method_idx = -1;
                for (int j = 0; j < method_count; j++) 
                {
                    if (strcmp(methods[j].signature, method->signature) == 0) 
                    {
                        method_idx = j;
                        break;
                    }
                }
                
                if (method_idx == -1 && method_count < UI_MAX_DISPLAY_ITEMS)
                    method_idx = method_count++;

                if (method_idx >= 0) 
                {
                    /* Copy signature */
                    strncpy(methods[method_idx].signature, method->signature, 
                           sizeof(methods[method_idx].signature) - 1);
                    methods[method_idx].signature[sizeof(methods[method_idx].signature) - 1] = '\0';
                    /* Direct field access */
                    methods[method_idx].call_count = method->call_count;
                    methods[method_idx].sample_count = method->sample_count;
                    methods[method_idx].total_time_ns = method->total_time_ns;
                    methods[method_idx].min_time_ns = method->min_time_ns;
                    methods[method_idx].max_time_ns = method->max_time_ns;
                    methods[method_idx].alloc_bytes = method->alloc_bytes;
                    methods[method_idx].peak_memory = method->peak_memory;
                    methods[method_idx].cpu_cycles = method->cpu_cycles;
                    methods[method_idx].last_updated = current_time;
                }
                break;
            }
            
            case COOPER_DATA_MEMORY_SAMPLE: {
                /* Clean access to memory data */
                cooper_memory_data_t *memory = &entry->data.memory;
                
                memory_data.last_updated = current_time;

                if (memory->thread_id == 0) {
                    /* Process-wide memory */
                    memory_data.process_memory = memory->process_memory;
                    /* Add to history */
                    if (memory_data.history_count < UI_MAX_HISTORY_POINTS) {
                        memory_data.memory_history[memory_data.history_count++] = memory->process_memory;
                    } else {
                        /* Shift history */
                        for (int j = 0; j < UI_MAX_HISTORY_POINTS - 1; j++) {
                            memory_data.memory_history[j] = memory_data.memory_history[j + 1];
                        }
                        memory_data.memory_history[UI_MAX_HISTORY_POINTS - 1] = memory->process_memory;
                    }
                } else {
                    /* Thread-specific memory */
                    int thread_idx = -1;
                    for (int j = 0; j < memory_data.active_threads; j++) {
                        if (memory_data.thread_ids[j] == memory->thread_id) {
                            thread_idx = j;
                            break;
                        }
                    }
                    
                    if (thread_idx == -1 && memory_data.active_threads < 10) {
                        thread_idx = memory_data.active_threads++;
                        memory_data.thread_ids[thread_idx] = memory->thread_id;
                    }

                    if (thread_idx >= 0) 
                        memory_data.thread_memory[thread_idx] = memory->thread_memory;
                }
                break;
            }
            
            case COOPER_DATA_OBJECT_ALLOC: {
                /* Clean access to object allocation data */
                struct cooper_object_alloc_data *alloc = &entry->data.object_alloc;
                
                /* Find or add object type */
                int obj_idx = -1;
                for (int j = 0; j < object_count; j++) {
                    if (strcmp(objects[j].class_name, alloc->class_signature) == 0) {
                        obj_idx = j;
                        break;
                    }
                }
                
                if (obj_idx == -1 && object_count < UI_MAX_DISPLAY_ITEMS)
                    obj_idx = object_count++;
                
                if (obj_idx >= 0) 
                {
                    /* Copy class signature to local CLI structure */
                    strncpy(objects[obj_idx].class_name, alloc->class_signature, 
                           sizeof(objects[obj_idx].class_name) - 1);
                    objects[obj_idx].class_name[sizeof(objects[obj_idx].class_name) - 1] = '\0';

                    /* Semantic field names */
                    objects[obj_idx].allocation_count = alloc->allocation_count;
                    objects[obj_idx].current_instances = alloc->current_instances;
                    objects[obj_idx].total_bytes = alloc->total_bytes;
                    objects[obj_idx].peak_instances = alloc->peak_instances;
                    objects[obj_idx].min_size = alloc->min_size;
                    objects[obj_idx].max_size = alloc->max_size;
                    objects[obj_idx].avg_size = alloc->avg_size;
                    objects[obj_idx].last_updated = current_time;
                }
                break;
            }
        }

        /* Mark entry as read */
        shm_ctx.status_shm->status[i] = ENTRY_READ;
    }
}

void debug_shared_memory() 
{
    if (!shm_ctx.data_shm || !shm_ctx.status_shm) {
        printf("DEBUG: No shared memory mapped\n");
        return;
    }
    
    printf("DEBUG: SHM Status - version=%u, max_entries=%u, next_write=%u\n",
           shm_ctx.data_shm->version, shm_ctx.data_shm->max_entries, 
           shm_ctx.data_shm->next_write_index);
    
    int ready_count = 0, read_count = 0, empty_count = 0;
    for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++) {
        switch (shm_ctx.status_shm->status[i]) 
        {
            case ENTRY_EMPTY: empty_count++; break;
            case ENTRY_READY: ready_count++; break;
            case ENTRY_READ: read_count++; break;
        }
    }
    
    printf("DEBUG: Status counts - Empty: %d, Ready: %d, Read: %d\n", 
           empty_count, ready_count, read_count);
}

int main() 
{
    if (init_cli_shm() != 0) 
    {
        printf("Error: Could not connect to Cooper agent shared memory\n");
        printf("Make sure the Cooper agent is running\n");
        return 1;
    }
    
    /* Initialize UI loader */
    loader = tui_loader_init("./libtui.so");
    if (!loader) {
        printf("Error: Could not load UI library\n");
        cleanup_cli_shm();
        return 1;
    }

    enable_raw_mode();
    get_terminal_size();
    
    signal(SIGWINCH, handle_sigwinch);
    signal(SIGINT, handle_sigint);
    
    while (1) {
        if (kbhit()) {
            char c = getch();
            switch (c) {
                case 'q':
                case 'Q':
                    goto cleanup_exit;
                case '1':
                    current_view = UI_VIEW_OVERVIEW;
                    break;
                case '2':
                    current_view = UI_VIEW_METHODS;
                    break;
                case '3':
                    current_view = UI_VIEW_MEMORY;
                    break;
                case '4':
                    current_view = UI_VIEW_OBJECTS;
                    break;
            }
        }
        
        /* Check for UI library changes and reload if necessary */
        tui_loader_check_and_reload(loader);

        read_shared_memory_data();

        /* Prepare UI context */
        tui_context_t ui_ctx = {
            .methods = methods,
            .objects = objects,
            .memory_data = &memory_data,
            .method_count = method_count,
            .object_count = object_count,
            .current_view = current_view,
            .terminal = { .width = term_width, .height = term_height, lines_drawn = 0 }
        };
        
        /* Draw using the loaded UI library */
        tui_loader_draw(loader, &ui_ctx);

        usleep(REFRESH_INTERVAL);
    }
    
cleanup_exit:
    disable_raw_mode();
    if (loader)
        tui_loader_cleanup(loader);

    cleanup_cli_shm();
    clear_screen();
    return 0;
}