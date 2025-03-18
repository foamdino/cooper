# Cooper

A jvm agent

## Build

Uses https://github.com/tsoding/nob.h for building to reduce dependencies (only need a compiler)

## TODO

* cleanup config file handling
* add assertions where appropriate
* add mechanism to record invocation counts (histogram?)
* need a fixed size data structure that we allocate at startup
* how to do sampling?
* add logging to a file, rip out printf