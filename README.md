# Cooper

A jvm agent

## Build

Uses https://github.com/tsoding/nob.h for building to reduce dependencies (only need a compiler)

## Usage
Compile and from the build location:
`java -agentpath:./libcooper.so=logfile=/tmp/jvmti.log com.github.foamdino.Test`
Need to have a `trace.ini` file in the working directory

## TODO

* cleanup config file handling
* add assertions where appropriate
* add some unit tests
* capture method parameters
* how to do method performance/timing