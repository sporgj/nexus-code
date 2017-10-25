#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

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
kinit $1
./openafs/src/aklog/aklog -d
