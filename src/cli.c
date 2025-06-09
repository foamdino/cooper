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

#define REFRESH_INTERVAL 100000  // Microseconds

static struct termios orig_termios;

void disable_raw_mode() 
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() 
{
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON); // Disable echo and canonical mode
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void clear_screen() 
{
    printf("\033[2J\033[H"); // ANSI escape: clear screen and move cursor to home
}

void draw_header() 
{
    printf("┌───────────── CLI Monitor ─────────────┐\n");
    printf("│ Press 'q' to quit                     │\n");
    printf("├────────────── Data View ──────────────┤\n");
}

void draw_data(int counter) 
{
    for (int i = 0; i < 5; ++i) {
        printf("│ Row %d: value = %-7d                │\n", i + 1, counter + i);
    }
    printf("└───────────────────────────────────────┘\n");
}

int kbhit() 
{
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

void handle_sigint(int sig) 
{
    (void)sig;
    disable_raw_mode();
    clear_screen();
    exit(0);
}

int main() 
{
    enable_raw_mode();
    signal(SIGINT, handle_sigint);

    int counter = 0;

    while (1) {
        if (kbhit()) {
            char c = getch();
            if (c == 'q') break;
        }

        clear_screen();
        draw_header();
        draw_data(counter);
        fflush(stdout);

        counter++; // Simulate data changing
        usleep(REFRESH_INTERVAL);
    }

    disable_raw_mode();
    clear_screen();
    return 0;
}