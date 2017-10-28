#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

openafs_dir=$HOME/nexus/openafs
afs_module=$openafs_dir/src/libafs/MODLOAD-$(uname -r)-MP/libafs.ko

set -e
set -x

module="nexus_mod"
mode="755"

sudo insmod $afs_module

major=$(awk -v MODULE=$module '$2==MODULE {print $1;}' /proc/devices)
sudo mknod /dev/$module c $major 0
sudo chown $USER /dev/$module
sudo chmod $mode /dev/$module

sudo $openafs_dir/src/afsd/afsd
kinit $1
$openafs_dir/src/aklog/aklog -d
