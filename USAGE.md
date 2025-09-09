# Usage

Run the application with the `-agentpath` parameter:

`java -agentpath:/opt/libcooper.so -jar my-app.jar`


## Configuration

The agent is configured via a file called `trace.ini`.


```
[sample_rate]
# Default sample rate for methods without a specific rate
# Setting to 1 means sample every call; higher values sample every Nth call
rate = 100

[method_signatures]
filters = [
    # Format: class_signature:method_name:method_signature:sample_rate:metrics
    
    # Sample every invocation (rate=1) of the a method in Test class
    # Collect time, memory, and CPU metrics  
    Lcom/github/foamdino/Test;:a:()Ljava/lang/String;:1:time,memory,cpu
    
    # Sample every 10th invocation of the b method in Test class
    # Collect only timing information
    Lcom/github/foamdino/Test;:b:()Ljava/lang/String;:10:time
    
    # Sample all methods in the Test class for comprehensive testing
    # Use '*' as wildcard for method name and signature
    Lcom/github/foamdino/Test;:*:*:1:time,memory,cpu
    
    # Sample the recursive method specifically to test deep call stacks
    Lcom/github/foamdino/Test;:recursiveTest:(I)V:1:time,memory,cpu
    
    # Sample exception-related methods
    Lcom/github/foamdino/Test;:exceptionTest:()V:1:time,memory,cpu
    Lcom/github/foamdino/Test;:throwingMethod:()V:1:time,memory,cpu
    Lcom/github/foamdino/Test;:deepThrowingMethod:()V:1:time,memory,cpu
]

[packages]
include = [
    # Each package is on a separate line
    Lcom/github/foamdino/
    #Lorg/springframework/
]

[sample_file_location]
path = "/tmp/method_metrics.txt"

[export]
method = "file" # only support file export for now
interval = 10   # Export metrics every 10 seconds for faster feedback during testing
```

This config file must be placed in the working directory.

The format of the file should be self-documenting. Lines starting with `#` are comments and are ignored.

The `[packages]` section allows you to specify exactly which packages to process. If this is an empty list `[]` then *all* classes in *all* packages will be scanned/processed. This will significantly slow down the application start-up, but is an option if you want to do that.

The `[method_signatures]` section contains the exact signatures and metrics you wish to inspect.

The data from these methods will be exported (along with some summary information) to the `[sample_file_location]` which in this example is `/tmp/method_metrics.txt`

## CLI

Along with the agent library, there is a command line tool that allows you to see a real-time view of (some) of the metrics.

This tool *must* be executed locally on the same host as the running application as the agent doesn't know or care about any networking - this is a design decision to limit the agent and to prevent any remote access.

The cli tool can be executed from anywhere on the filesystem and will attach to the agent.


