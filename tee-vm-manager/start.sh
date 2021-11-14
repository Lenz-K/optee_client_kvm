#!/bin/bash
ROOTFS=/media/ramdisk
export PATH=$ROOTFS/usr/bin:$ROOTFS/usr/lib:$ROOTFS/usr/sbin
export LD_LIBRARY_PATH=$PATH

tee-supplicant
xtest

