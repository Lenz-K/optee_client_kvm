#!/bin/bash
ROOTFS=/media/ramdisk
export PATH=$ROOTFS/usr/bin:$ROOTFS/usr/lib
export LD_LIBRARY_PATH=$ROOTFS/usr/bin:$ROOTFS/usr/lib

xtest

