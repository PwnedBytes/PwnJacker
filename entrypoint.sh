#!/bin/sh
# entrypoint.sh – Docker entrypoint script

# If no arguments passed, show help
if [ $# -eq 0 ]; then
    exec /usr/local/bin/pwnjacker -h
else
    exec /usr/local/bin/pwnjacker "$@"
fi