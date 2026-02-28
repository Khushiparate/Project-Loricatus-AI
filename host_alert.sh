#!/bin/bash
MSG="$1"

notify-send "NIDS ALERT" "$MSG"
paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga

