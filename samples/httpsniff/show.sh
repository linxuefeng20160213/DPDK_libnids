#!/bin/sh

kill -s 1 `cat /var/run/httpsniff.pid`
cat /tmp/httpsniff_status.txt

