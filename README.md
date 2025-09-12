# Cooper

A jvm agent

## Build

Uses https://github.com/tsoding/nob.h for building to reduce dependencies (only need a compiler)

## Usage

Compile and from the build location:
`java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test`
Need to have a `trace.ini` file in the working directory

## Code metrics


## Valgrind

```
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
         --track-origins=yes --verbose --log-file=valgrind-log.txt \
         java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test
```

## strace & friends
```
strace -o trace.log -f java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test
```

## async-profiler
This is the main open source profiler/agent tool available. Need to work out the equivalent params so we can compare like-for-like (as much as we can)
```
java -agentpath:/home/kev/projects/async-profiler/build/lib/libasyncProfiler.so=start,cpu,flat=20,loop=60 -jar java-src/target/spring-boot-test-0.0.1-SNAPSHOT.jar
```
## Misc TODO

* using tracing tools to uncover how many syscalls/librarycalls are made in the code
* cleanup config file handling
* add assertions where appropriate
* add iterator to hashtable impl (maybe)

## Next steps

* call stack sampling:
- use jvmtiEnv->GetStackTrace.
- Can be sampled at intervals in a background thread (e.g. 100ms).
  - already have a background threads setup so the structure is present
- Useful to implement Top N methods by time or Hot method identification.
  - will need to implement Top N methods by (time/cpu etc)

* capture exception metrics for methods 
  - take the method_metrics_soa add exception count
  - hot methods by exceptions

## Threads and pinning to cores
At some point we will want to pin specific threads to different cores. 
We need to extend the cpu.h lib to support retrieving the number of cores.

## Features TODO

* Summary
  * Top N objects allocated (v1 done)
  * Top N methods by time/cpu cycles/memory allocations/syscalls
* Methods
  * Entry/exit tracking (v1 done)
  * Capturing method params
  * Recording method execution times (v1 done)
  * call stack sampling
* Exceptions
  * Capturing exception details (v1 done)
  * Tracking exception throw points (v1 done)
  * Record stack traces for exceptions
  * Paramter values at exception points (v1 done)
* Mem
  * Object allocation tracking
  * Object lifetime monitoring
  * Mem usage stats
    * Process memory (v1 done)
    * Thread memory
    * Per method allocted bytes (v1 done)
  * Heap walk and object graph analysis
* Threads
  * Thread creation/destruction tracking
  * Thread state changes
  * Thread contention analysis
  * Lock/synchronisation event tracing
* Perf
  * CPU sampling
  * Method level perf metrics
  * Hot method identification
  * Execution time distributions
* Systems integration
  * OS-level system call tracing (eBPF/ftrace etc)
  * Native lib load/unload events
  * CPU clock cycles integration (v1 done)

<!-- TOKEI-START -->
## 📊 Code Statistics

**Generated:** 2025-09-09 11:29:44 UTC for release `v0.0.3-alpha`

This report tracks project complexity to maintain our goal of a minimal, dependency-free JVM agent.

```
===============================================================================
 Language            Files        Lines         Code     Comments       Blanks
===============================================================================
 C                      24        10416         7208         1614         1594
 C Header               24         4058         2431         1081          546
 Shell                   2          301          216           53           32
 Java                    3          256          142           62           52
 Batch                   1          149          134            0           15
 INI                     2           86           42           26           18
 XML                     1           37           35            0            2
 BASH                    1           35           21            7            7
-------------------------------------------------------------------------------
 Markdown                4          327            0          231           96
 |- BASH                 1            7            4            2            1
 |- INI                  1           23           13            5            5
 (Total)                            357           17          238          102
===============================================================================
 Total                  62        15665        10229         3074         2362
===============================================================================
```

**Key Metrics:**
- **Total C Lines:** 21
- **Total C Files:** 46
- **External Dependencies:** 0 (excluding system libraries)
- **Build Tool:** Custom (nob.c)

*Lower complexity = easier maintenance, faster builds, and reduced attack surface.*
<!-- TOKEI-END -->
