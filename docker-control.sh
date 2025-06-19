#!/bin/bash

case "$1" in
    "connect")
        echo "Connecting to server control interface..."
        docker exec -it tactical-data-server bash
        ;;
    "cmd")
        if [ -z "$2" ]; then
            echo "Usage: $0 cmd <command>"
            echo "Available commands: list, stop_tcp, start_tcp, stats"
            exit 1
        fi
        echo "Sending command: $2"
        echo "$2" | nc localhost 9090
        ;;
    "shell")
        docker exec -it tactical-data-server bash
        ;;
    *)
        echo "Usage: $0 {connect|cmd|shell}"
        echo "  connect - Interactive control session"
        echo "  cmd <command> - Send single command"
        echo "  shell - Open bash in container"
        ;;
esac