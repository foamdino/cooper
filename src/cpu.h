/*
 * SPDX-FileCopyrightText: (c) 2025 Kev Jackson <foamdino@gmail.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CPU_H
#define CPU_H

#include <stdint.h>

#ifdef __x86_64__

/* Cache line size is 64 on x86_64 */
#define CACHE_LINE_SZ 64

/**
 * Read the Time Stamp Counter at the start of a measurement period
 */
static __inline__ uint64_t rdtsc_start(void)
{
    /* rdtsc instruction returns a 64bit value split across 2 32bit registers
    edx for the high bits
    eax for the low bits
    */
    unsigned cycles_high_bits; 
    unsigned cycles_low_bits;
    /* Keep the code as is, do not optimise away etc */
    __asm__ __volatile__ (
        "CPUID\n\t"  /*Serialize - CPUID prevents the processor from re-ordering the RDTSC instruction */
        "RDTSC\n\t" /*Read Time Stamp Counter instruction */
        "mov %%edx, %0\n\t" /* move the content of edx into the first output variable - cycle_high_bits */
        "mov %%eax, %1\n\t" /* move the content of eax into the second output variable - cycle_low_bits */
        : "=r" (cycles_high_bits), "=r" (cycles_low_bits) /* Output operands */
        : /* no input operands */
        : "%rax", "%rbx", "%rcx", "%rdx"); /* List of 'clobbered' registers  (CPUID  modifies the 64bit version rax etc)*/

    return ((uint64_t)cycles_high_bits << 32) | cycles_low_bits;
}

/**
 * Read the Time Stamp Counter at the end of a measurement period
 */
static __inline__ uint64_t rdtsc_end(void)
{
    unsigned cycles_high_bits;
    unsigned cycles_low_bits;
    /* Keep the code as is, do not optimise away etc */
    __asm__ __volatile__ (
        "RDTSCP\n\t" /* Read timestamp counter and processor ID */
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t" /* Serialize to prevent reordering */
        : "=r" (cycles_high_bits), "=r" (cycles_low_bits)
        : /* no input operands */
        : "%rax", "%rbx", "%rcx", "%rdx");
        
    return ((uint64_t)cycles_high_bits << 32) | cycles_low_bits;   
}
#endif

#ifdef __aarch64__

/* Cache line size on aarch64 can be 64 or 128 so we use 128 */
#define CACHE_LINE_SZ 128

/**
 * Reads the current virtual count value from the system register CNTVCT_EL0.
 * This value represents the number of ticks since an arbitrary point in time.
 * 
 * @return uint64_t number of ticks
 */
static inline uint64_t read_cntvct(void)
{
    uint64_t cnt;
    asm volatile("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
}

/**
 * Reads the frequency of the system counter from the CNTFRQ_EL0 register.
 * This value indicates how many ticks occur per second, allowing conversion
 * from ticks to time units (e.g., microseconds, milliseconds).
 * 
 * @return uint32_t frequency of system counter
 */
static inline uint32_t read_cntfrq(void)
{
    uint32_t frq;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    return frq;
}
#endif

/**
 * Call to get the CPU cycle count from cpu registers
 */
static __inline__ uint64_t cycles_start(void)
{
#ifdef __x86_64__
    return rdtsc_start();
#elif defined(__aarch64__)
    return read_cntvct();
#else
    return 0;
#endif
}

/**
 * Call to get the CPU cycle count from cpu registers
 */
static __inline__ uint64_t cycles_end(void)
{
#ifdef __x86_64__
    return rdtsc_end();
#elif defined(__aarch64__)
    return read_cntvct();
#else
    return 0;
#endif
}

#endif /* CPU_H */