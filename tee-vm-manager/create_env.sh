mkdir /media/ramdisk
chmod 777 /media/ramdisk
mount -t tmpfs -o size=250M none /media/ramdisk
gzip -d rootfs.cpio.gz
cpio -idm -D /media/ramdisk < rootfs.cpio
cp tee.elf /media/ramdisk/usr/lib

