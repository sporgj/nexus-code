#!/bin/bash
set -e
set -x

module="ucafs_mod"
mode="755"

sudo insmod openafs/src/libafs/MODLOAD-$(uname -r)-MP/libafs.ko

major=$(awk -v MODULE=$module '$2==MODULE {print $1;}' /proc/devices)
sudo mknod /dev/$module c $major 0
sudo chown $USER /dev/$module
sudo chmod $mode /dev/$module

sudo ./openafs/src/afsd/afsd
kinit djoko
./openafs/src/aklog/aklog -d
