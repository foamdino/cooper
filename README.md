# Cooper

A jvm agent

## Build

Uses https://github.com/tsoding/nob.h for building to reduce dependencies (only need a compiler)

## Usage
Compile and from the build location:
`java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test`
Need to have a `trace.ini` file in the working directory

## Misc TODO

* cleanup config file handling
* add assertions where appropriate

## Features TODO

* Methods
  * Entry/exit tracking (done)
  * Capturing method params
  * Recording method execution times
  * call stack sampling
* Exceptions
  * Capturing exception details
  * Tracking exception throw points
  * Record stack traces for exceptions
  * Paramter values at exception points
* Mem
  * Object allocation tracking
  * Object lifetime monitoring
  * Mem usage stats
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
  * CPU clock cycles integration