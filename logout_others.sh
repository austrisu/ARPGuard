#!/bin/bash

# Get your own TTY
my_tty=$(who | grep "$(whoami)" | awk '{print $2}')

# Iterate over logged-in users and log them out
who | while read -r user line; do
  tty=$(echo "$line" | awk '{print $2}')
  if [[ "$tty" != "$my_tty" ]]; then
    echo "Logging out user $user on TTY $tty"
    pkill -HUP -t "$tty"
  fi
done