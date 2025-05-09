#!/bin/bash

AGENT_PATH="/home/kev/projects/cooper/build/libcooper.so"
CLASSES_DIR="/home/kev/projects/cooper/build"
MAIN_CLASS="com.github.foamdino.Test"
WORKSPACE_DIR="/home/kev/projects/cooper"

# Start JVM in background
java -agentpath:$AGENT_PATH -cp "$CLASSES_DIR" $MAIN_CLASS &
JVM_PID=$!

echo "Started JVM running $MAIN_CLASS with PID: $JVM_PID"

# Wait briefly to make sure the process is up
sleep 2

# Generate launch.json dynamically on the remote VM
cat <<EOF > "${WORKSPACE_DIR}/.vscode/launch.json"
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Attach to JVM (auto)",
      "type": "cppdbg",
      "request": "attach",
      "program": "/proc/$JVM_PID/exe",
      "processId": "$JVM_PID",
      "MIMode": "gdb",
      "miDebuggerPath": "/usr/bin/gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        }
      ]
    }
  ]
}
EOF

echo "launch.json written — switch to VSCode Debug tab and start 'Attach to JVM (auto)'"
