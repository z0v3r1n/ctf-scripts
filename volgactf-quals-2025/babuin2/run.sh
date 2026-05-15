#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -monitor none \
    -cpu qemu64,+smep,+smap \
    -initrd "./initramfs.cpio.gz" \
    -drive file=flag.txt,format=raw \
    -snapshot -s
