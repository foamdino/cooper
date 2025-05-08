# Cooper JVM Agent - Integration Guide

## Overview

Cooper is a JVM agent that monitors method execution with minimal impact on application performance. It collects detailed metrics about method calls, memory usage, and execution time.

## Building the Agent

nob is available from https://github.com/tsoding/nob.h

The build system uses a minimal C approach to reduce external dependencies:

```bash
# Compile the agent
./nob

# If nob doesn't exist yet, bootstrap it first
cc -o nob nob.c
./nob
```

This will produce `build/libcooper.so` which is the agent library.

## Configuration

Cooper uses a configuration file (`trace.ini`) to control its behavior:

1. Create a `trace.ini` file in your working directory using the following template:

```ini
[sample_rate]
# Default sample rate
rate = 100

[method_signatures]
filters = [
    # Format: class_signature:method_name:method_signature:sample_rate:metrics
    # Sample every call (rate=1) of method process in MyService class
    Lcom/example/MyService;:process:(Ljava/lang/String;)V:1:time,memory,cpu
    
    # Sample every 10th call of method query in Repository
    Lcom/example/Repository;:query:()Ljava/util/List;:10:time,memory
    
    # Sample all methods in Utils class
    Lcom/example/Utils;:*:*:100:time
]

[sample_file_location]
path = "/tmp/method_metrics.txt"

[export]
method = "file"
interval = 60
```

### Configuration Options

- **sample_rate**: Default sampling rate for methods not explicitly specified
- **method_signatures.filters**: Array of method filters with format:
  - `class_signature:method_name:method_signature:sample_rate:metrics`
  - Wildcards (`*`) can be used for method_name and method_signature
  - Available metrics: `time`, `memory`, `cpu`
- **sample_file_location.path**: Path where metrics will be exported
- **export.method**: Export method (currently only `file` is supported)
- **export.interval**: How frequently (in seconds) metrics are exported

## Using the Agent

To use Cooper with your Java application:

```bash
java -agentpath:/path/to/libcooper.so=logfile=/tmp/jvmti.log YourJavaApplication
```

### Agent Options

- **logfile**: Path to the agent's log file (defaults to stdout if not specified)

## Interpreting the Output

The agent produces two main outputs:

### 1. Agent Log

Contains real-time information about agent operation, method entries/exits, and exception details.

### 2. Metrics Export

Exported to the configured file location with the format:

```
# Method Metrics Export - [timestamp]
# Format: signature, call_count, sample_count, total_time_ns, avg_time_ns, min_time_ns, max_time_ns, alloc_bytes, peak_memory, cpu_cycles

com.example.Service processRequest ()V,1500,15,52500000,3500000,1200000,10500000,2048000,512000,0
```

Fields explanation:
- **signature**: Full method signature
- **call_count**: Total number of times the method was called
- **sample_count**: Number of times the method was sampled
- **total_time_ns**: Total execution time in nanoseconds
- **avg_time_ns**: Average execution time in nanoseconds
- **min_time_ns**: Minimum execution time in nanoseconds
- **max_time_ns**: Maximum execution time in nanoseconds
- **alloc_bytes**: Total bytes allocated during method execution
- **peak_memory**: Peak memory usage in bytes
- **cpu_cycles**: CPU cycles used (if supported by platform)

## Monitoring Considerations

### Impact on Application Performance

Cooper is designed to minimize overhead:
- Arena-based memory management avoids heap allocations in critical paths
- Sampling approach reduces overhead for frequently called methods
- Thread-local storage minimizes lock contention

For production use, consider:
1. Using higher sampling rates (e.g., 100 or 1000) for high-frequency methods
2. Focusing on specific problematic methods rather than instrumenting everything
3. Setting longer export intervals (e.g., 300 seconds) to reduce I/O impact

### Memory Usage

The agent pre-allocates memory arenas to avoid runtime allocations:
- **Exception arena**: 1MB
- **Log arena**: 1MB
- **Sample arena**: 2MB
- **Metrics arena**: 8MB

Total memory overhead is approximately 12-15MB depending on configuration.

## Troubleshooting

### Common Issues

1. **Agent fails to load**
   - Ensure the path to the agent is correct
   - Check if the library is compiled for the correct architecture (32/64 bit)

2. **No metrics being captured**
   - Verify method signatures in configuration match actual class signatures
   - Check the agent log for error messages
   - Ensure the working directory contains trace.ini

3. **JVM crashes or exceptions**
   - Check agent logs for error messages
   - Increase sampling rates to reduce overhead
   - Limit the number of instrumented methods

## Advanced Usage

### Capturing Exceptions

The agent automatically captures exception information, including:
- Exception type and message
- Method where exception occurred
- Parameter values at exception point

This information is logged to the agent's log file.

### Memory Tracking

Memory metrics include:
- **alloc_bytes**: Total bytes allocated during method execution
- **peak_memory**: Peak memory usage during method execution

Note that memory tracking has some limitations:
- Small allocations may be missed due to JVM optimizations
- Some native memory allocations may not be tracked

## Security Considerations

The Cooper agent:
- Does not transmit data over the network
- Does not modify application code beyond method instrumentation
- Requires access to the filesystem for logging and metrics export