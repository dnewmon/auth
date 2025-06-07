#!/bin/bash

while true; do
    claude "Work on the project."
    echo "Press ESC to cancel..."
    read -t 10 -n 1 key
    if [[ $key = $'\e' ]]; then
        exit 0
    fi
done
