# Cooper

A jvm agent

## Build

Uses https://github.com/tsoding/nob.h for building to reduce dependencies (only need a compiler)

## Usage

Compile and from the build location:
`java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test`
Need to have a `trace.ini` file in the working directory

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
