#!/bin/sh

cp /flag.txt "/srv/app/flag-$(md5sum /flag.txt | awk '{print $1}').txt"
echo "no flag" > /flag.txt

socat tcp-listen:6702,reuseaddr,fork exec:"su -c ./chall pwn"
