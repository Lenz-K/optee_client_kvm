#!/bin/bash
mkdir /media/ramdisk
chmod 777 /media/ramdisk
mount -t tmpfs -o size=250M none /media/ramdisk

CPIO="./bin/rootfs.cpio"
if [ ! -f "$CPIO" ]; then
    gzip -dk ./bin/rootfs.cpio.gz
fi

cpio -idm -D /media/ramdisk < $CPIO
cp ./bin/tee.elf /media/ramdisk/usr/bin
