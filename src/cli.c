/* src/cli.c */
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

#include "shared_mem.h"

#define REFRESH_INTERVAL 250000  /* 250ms */
#define MAX_DISPLAY_ITEMS 20
#define MAX_HISTORY_POINTS 100

typedef enum {
    VIEW_OVERVIEW = 0,
    VIEW_METHODS = 1,
    VIEW_MEMORY = 2,
    VIEW_OBJECTS = 3,
    VIEW_COUNT
} view_mode_e;

typedef struct {
    cooper_data_shm_t *data_shm;
    cooper_status_shm_t *status_shm;
    int data_fd;
    int status_fd;
} cli_shm_context_t;

typedef struct {
    char signature[COOPER_MAX_SIGNATURE_LEN];
    uint64_t call_count;
    uint64_t total_time_ns;
    uint64_t avg_time_ns;
    uint64_t alloc_bytes;
    time_t last_updated;
} method_display_t;

typedef struct {
    char class_name[COOPER_MAX_SIGNATURE_LEN];
    uint64_t allocation_count;
    uint64_t total_bytes;
    uint64_t current_instances;
    uint64_t avg_size;
    time_t last_updated;
} object_display_t;

typedef struct {
    uint64_t process_memory;
    uint64_t thread_memory[10]; /* Track up to 10 threads */
    uint64_t thread_ids[10];
    int active_threads;
    uint64_t memory_history[MAX_HISTORY_POINTS];
    int history_count;
    time_t last_updated;
} memory_display_t;

static struct termios orig_termios;
static int term_width = 80;
static int term_height = 24;
static int lines_drawn = 0;
static view_mode_e current_view = VIEW_OVERVIEW;
static cli_shm_context_t shm_ctx = {0};

/* Display data structures */
static method_display_t methods[MAX_DISPLAY_ITEMS];
static object_display_t objects[MAX_DISPLAY_ITEMS];
static memory_display_t memory_data = {0};
static int method_count = 0;
static int object_count = 0;

/* Terminal handling functions */
void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void get_terminal_size() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        term_width = w.ws_col;
        term_height = w.ws_row;
    }
}

void handle_sigwinch(int sig) {
    (void)sig;
    get_terminal_size();
}

void handle_sigint(int sig) {
    (void)sig;
    disable_raw_mode();
    printf("\033[2J\033[H");
    exit(0);
}

void clear_screen() {
    printf("\033[2J\033[H");
}

int kbhit() {
    struct timeval tv = { 0L, 0L };
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    return select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
}

char getch() {
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

void cleanup_cli_shm() {
    if (shm_ctx.data_shm && shm_ctx.data_shm != MAP_FAILED) {
        munmap(shm_ctx.data_shm, sizeof(cooper_data_shm_t));
    }
    if (shm_ctx.status_shm && shm_ctx.status_shm != MAP_FAILED) {
        munmap(shm_ctx.status_shm, sizeof(cooper_status_shm_t));
    }
    if (shm_ctx.data_fd > 0) close(shm_ctx.data_fd);
    if (shm_ctx.status_fd > 0) close(shm_ctx.status_fd);
}

/* Data reading and processing functions */
void read_shared_memory_data() {
    if (!shm_ctx.data_shm || !shm_ctx.status_shm) return;
    
    time_t current_time = time(NULL);
    
    for (uint32_t i = 0; i < COOPER_MAX_ENTRIES; i++) {
        /* Only read entries that haven't been read yet */
        if (shm_ctx.status_shm->status[i] == ENTRY_READY) {
            cooper_method_metric_data_t *entry = &shm_ctx.data_shm->metrics[i];
            
            /* Skip empty entries (check if there's actual data) */
            if (entry->data_type == 0)
                continue;
            

            switch (entry->data_type)
            {
                case COOPER_DATA_METHOD_METRIC:
                    /* Find or add method */
                    int method_idx = -1;
                    for (int j = 0; j < method_count; j++) {
                        if (strcmp(methods[j].signature, entry->signature) == 0) {
                            method_idx = j;
                            break;
                        }
                    }
                    
                    if (method_idx == -1 && method_count < MAX_DISPLAY_ITEMS)
                        method_idx = method_count++;
                    
                    if (method_idx >= 0) {
                        strncpy(methods[method_idx].signature, entry->signature, 
                            sizeof(methods[method_idx].signature) - 1);
                        methods[method_idx].call_count = entry->call_count;
                        methods[method_idx].total_time_ns = entry->total_time_ns;
                        methods[method_idx].avg_time_ns = entry->sample_count > 0 ? 
                            entry->total_time_ns / entry->sample_count : 0;
                        methods[method_idx].alloc_bytes = entry->alloc_bytes;
                        methods[method_idx].last_updated = current_time;
                    }
                    break;

                case COOPER_DATA_MEMORY_SAMPLE:
                    /* Memory sample fields are mapped to cooper_method_metric_data_t:
                    * process_memory -> alloc_bytes
                    * thread_id -> call_count  
                    * thread_memory -> peak_memory
                    */
                    uint64_t thread_id = entry->call_count;
                    uint64_t process_memory = entry->alloc_bytes;
                    uint64_t thread_memory = entry->peak_memory;
                    
                    if (thread_id == 0) {
                        /* Process memory */
                        memory_data.process_memory = process_memory;
                        
                        /* Add to history */
                        if (memory_data.history_count < MAX_HISTORY_POINTS) {
                            memory_data.memory_history[memory_data.history_count++] = process_memory;
                        } else {
                            /* Shift history */
                            for (int j = 0; j < MAX_HISTORY_POINTS - 1; j++) {
                                memory_data.memory_history[j] = memory_data.memory_history[j + 1];
                            }
                            memory_data.memory_history[MAX_HISTORY_POINTS - 1] = process_memory;
                        }
                    } else {
                        /* Thread memory */
                        int thread_idx = -1;
                        for (int j = 0; j < memory_data.active_threads; j++) {
                            if (memory_data.thread_ids[j] == thread_id) {
                                thread_idx = j;
                                break;
                            }
                        }
                        
                        if (thread_idx == -1 && memory_data.active_threads < 10) {
                            thread_idx = memory_data.active_threads++;
                            memory_data.thread_ids[thread_idx] = thread_id;
                        }
                        
                        if (thread_idx >= 0)
                            memory_data.thread_memory[thread_idx] = thread_memory;
                    }
                    memory_data.last_updated = current_time;
                    break;

                case COOPER_DATA_OBJECT_ALLOC:
                    /* Object allocation fields are mapped to cooper_method_metric_data_t:
                    * class_signature -> signature
                    * allocation_count -> call_count
                    * total_bytes -> alloc_bytes
                    * current_instances -> sample_count
                    * min_size -> total_time_ns
                    * max_size -> min_time_ns  
                    * avg_size -> max_time_ns
                    * peak_instances -> peak_memory
                    */
                    
                    /* Find or add object type */
                    int obj_idx = -1;
                    for (int j = 0; j < object_count; j++) {
                        if (strcmp(objects[j].class_name, entry->signature) == 0) {
                            obj_idx = j;
                            break;
                        }
                    }
                    
                    if (obj_idx == -1 && object_count < MAX_DISPLAY_ITEMS)
                        obj_idx = object_count++;
                    
                    if (obj_idx >= 0) {
                        strncpy(objects[obj_idx].class_name, entry->signature, 
                            sizeof(objects[obj_idx].class_name) - 1);
                        objects[obj_idx].allocation_count = entry->call_count;
                        objects[obj_idx].total_bytes = entry->alloc_bytes;
                        objects[obj_idx].current_instances = entry->sample_count;
                        objects[obj_idx].avg_size = entry->max_time_ns;
                        objects[obj_idx].last_updated = current_time;
                    }
                    break;
            }
            /* IMPORTANT: Mark entry as read so agent can reuse this slot */
            shm_ctx.status_shm->status[i] = ENTRY_READ;
        }
    }
}

/* Modify the printf functions to track lines */
static void safe_printf(const char *format, ...) 
{
    if (lines_drawn >= term_height - 1) return; /* Don't exceed terminal height */
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    /* Count newlines in the format string */
    for (const char *p = format; *p; p++) {
        if (*p == '\n') lines_drawn++;
    }
}

/* Visualization functions */
void draw_header() 
{
    const char* view_names[] = {"Overview", "Methods", "Memory", "Objects"};
    char title[256];
    snprintf(title, sizeof(title), " Cooper Monitor - %s ", view_names[current_view]);
    
    int title_len = strlen(title);
    int padding = (term_width - title_len) / 2;
    
    safe_printf("┌");
    for (int i = 0; i < term_width - 2; i++) safe_printf("─");
    safe_printf("┐\n");
    
    safe_printf("│");
    for (int i = 0; i < padding; i++) safe_printf(" ");
    safe_printf("%s", title);
    for (int i = padding + title_len; i < term_width - 1; i++) safe_printf(" ");
    safe_printf("│\n");
    
    safe_printf("├");
    for (int i = 0; i < term_width - 2; i++) safe_printf("─");
    safe_printf("┤\n");
    
    safe_printf("│ Keys: [1-4] Switch views  [q] Quit");
    for (int i = 34; i < term_width - 1; i++) safe_printf(" ");
    safe_printf("│\n");
    
    safe_printf("├");
    for (int i = 0; i < term_width - 2; i++) safe_printf("─");
    safe_printf("┤\n");
}

void draw_bar_chart(const char* title, const char* items[], uint64_t values[], int count, uint64_t max_val) {
    printf("│ %s\n", title);
    printf("│\n");
    
    int max_name_len = 25;
    int bar_width = term_width - max_name_len - 15; /* Leave space for value and borders */
    
    if (bar_width < 10) bar_width = 10;
    
    for (int i = 0; i < count && i < term_height - 10; i++) {
        printf("│ %-*.*s", max_name_len, max_name_len, items[i]);
        
        int bar_len = max_val > 0 ? (values[i] * bar_width) / max_val : 0;
        if (bar_len > bar_width) bar_len = bar_width;
        
        printf(" [");
        for (int j = 0; j < bar_len; j++) printf("█");
        for (int j = bar_len; j < bar_width; j++) printf(" ");
        printf("] %8lu\n", (unsigned long)values[i]);
    }
}

void draw_memory_history() {
    printf("│ Process Memory History (MB)\n");
    printf("│\n");
    
    if (memory_data.history_count < 2) {
        printf("│ Collecting data...\n");
        return;
    }
    
    /* Find min/max for scaling */
    uint64_t min_mem = memory_data.memory_history[0];
    uint64_t max_mem = memory_data.memory_history[0];
    
    for (int i = 1; i < memory_data.history_count; i++) {
        if (memory_data.memory_history[i] < min_mem) min_mem = memory_data.memory_history[i];
        if (memory_data.memory_history[i] > max_mem) max_mem = memory_data.memory_history[i];
    }
    
    int chart_height = 8;
    int chart_width = term_width - 10;
    
    /* Draw the chart from top to bottom */
    for (int row = 0; row < chart_height; row++) {
        printf("│ ");
        uint64_t threshold = max_mem - ((max_mem - min_mem) * row) / chart_height;
        
        for (int col = 0; col < memory_data.history_count && col < chart_width; col++) {
            if (memory_data.memory_history[col] >= threshold) {
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
           (unsigned long)(memory_data.process_memory / 1024 / 1024));
}

void draw_histogram(const char* title, uint64_t values[], int count) {
    printf("│ %s\n", title);
    printf("│\n");
    
    if (count == 0) 
    {
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
    
    if (max_val == min_val) 
    {
        printf("│ All values are identical: %lu\n", (unsigned long)min_val);
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

void draw_overview() {
    safe_printf("│ System Overview\n");
    safe_printf("│\n");
    safe_printf("│ Process Memory: %lu MB\n", (unsigned long)(memory_data.process_memory / 1024 / 1024));
    safe_printf("│ Active Threads: %d\n", memory_data.active_threads);
    safe_printf("│ Tracked Methods: %d\n", method_count);
    safe_printf("│ Object Types: %d\n", object_count);
    safe_printf("│\n");
    
    /* Show top methods by call count */
    if (method_count > 0) {
        safe_printf("│ Top Methods by Calls:\n");
        for (int i = 0; i < method_count && i < 5; i++) {
            char short_name[50];
            const char* last_slash = strrchr(methods[i].signature, '/');
            const char* display_name = last_slash ? last_slash + 1 : methods[i].signature;
            snprintf(short_name, sizeof(short_name), "%.45s", display_name);
            
            safe_printf("│   %-45s %8lu calls\n", short_name, (unsigned long)methods[i].call_count);
        }
    }
}

void draw_methods_view() {
    if (method_count == 0) {
        printf("│ No method data available\n");
        return;
    }
    
    /* Show methods by average execution time */
    const char* method_names[MAX_DISPLAY_ITEMS];
    uint64_t avg_times[MAX_DISPLAY_ITEMS];
    uint64_t max_time = 0;
    
    for (int i = 0; i < method_count; i++) {
        const char* last_slash = strrchr(methods[i].signature, '/');
        method_names[i] = last_slash ? last_slash + 1 : methods[i].signature;
        avg_times[i] = methods[i].avg_time_ns / 1000; /* Convert to microseconds */
        if (avg_times[i] > max_time) max_time = avg_times[i];
    }
    
    draw_bar_chart("Method Execution Times (μs)", method_names, avg_times, method_count, max_time);
}

void draw_memory_view() {
    draw_memory_history();
    printf("│\n");
    
    if (memory_data.active_threads > 0) {
        printf("│ Thread Memory Usage (MB):\n");
        for (int i = 0; i < memory_data.active_threads; i++) {
            printf("│ Thread %lu: %lu MB\n", 
                   (unsigned long)memory_data.thread_ids[i],
                   (unsigned long)(memory_data.thread_memory[i] / 1024 / 1024));
        }
    }
}

void draw_objects_view() 
{
    if (object_count == 0) {
        printf("│ No object allocation data available\n");
        return;
    }
    
    /* Show objects by total bytes allocated */
    const char* object_names[MAX_DISPLAY_ITEMS];
    uint64_t bytes_allocated[MAX_DISPLAY_ITEMS];
    uint64_t max_bytes = 0;
    
    for (int i = 0; i < object_count; i++) {
        const char* last_slash = strrchr(objects[i].class_name, '/');
        object_names[i] = last_slash ? last_slash + 1 : objects[i].class_name;
        bytes_allocated[i] = objects[i].total_bytes;
        if (bytes_allocated[i] > max_bytes) max_bytes = bytes_allocated[i];
    }
    
    draw_bar_chart("Object Allocations (bytes)", object_names, bytes_allocated, object_count, max_bytes);
}

void draw_footer() {
    safe_printf("└");
    for (int i = 0; i < term_width - 2; i++) safe_printf("─");
    safe_printf("┘\n");
}

void draw_ui() {
    clear_screen();
    lines_drawn = 0; /* reset line counter */
    draw_header();
    
    switch (current_view) {
        case VIEW_OVERVIEW:
            draw_overview();
            break;
        case VIEW_METHODS:
            draw_methods_view();
            break;
        case VIEW_MEMORY:
            draw_memory_view();
            break;
        case VIEW_OBJECTS:
            draw_objects_view();
            break;
        default:
            break;
    }
    
    /* Fill remaining space */
    int lines_used = 8; /* Header + footer estimate */
    for (int i = lines_used; i < term_height - 1; i++) {
        safe_printf("│");
        for (int j = 0; j < term_width - 2; j++) safe_printf(" ");
        safe_printf("│\n");
    }
    
    draw_footer();
    fflush(stdout);
}

void debug_shared_memory() {
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
    
    /* Show first few ready entries */
    for (uint32_t i = 0; i < 5 && i < COOPER_MAX_ENTRIES; i++) {
        if (shm_ctx.status_shm->status[i] == ENTRY_READY) {
            cooper_method_metric_data_t *entry = &shm_ctx.data_shm->metrics[i];
            printf("DEBUG: Ready entry[%u]: type=%d, sig='%s'\n", 
                   i, entry->data_type, entry->signature);
        }
    }
}

int main() 
{
    if (init_cli_shm() != 0) 
    {
        printf("Error: Could not connect to Cooper agent shared memory\n");
        printf("Make sure the Cooper agent is running\n");
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
                    current_view = VIEW_OVERVIEW;
                    break;
                case '2':
                    current_view = VIEW_METHODS;
                    break;
                case '3':
                    current_view = VIEW_MEMORY;
                    break;
                case '4':
                    current_view = VIEW_OBJECTS;
                    break;
            }
        }
        
        read_shared_memory_data();

        /* Add debug output every few seconds */
        static int debug_counter = 0;
        if (++debug_counter % 20 == 0) { /* Every ~5 seconds */
            debug_shared_memory();
        }
        draw_ui();
        usleep(REFRESH_INTERVAL);
    }
    
cleanup_exit:
    disable_raw_mode();
    cleanup_cli_shm();
    clear_screen();
    return 0;
}