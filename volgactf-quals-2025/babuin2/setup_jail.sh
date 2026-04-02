#!/bin/sh
# For QEMU temporary disk images
mount -t tmpfs -o size=4M,rw,nodev,nosuid,noexec tmpfs /srv/var/tmp/
exec /jail/run