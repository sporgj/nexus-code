#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

openafs_dir=$HOME/nexus/openafs
afs_module=$openafs_dir/src/libafs/MODLOAD-$(uname -r)-MP/libafs.ko

set -e
set -x

sudo insmod $afs_module

sudo chown $USER /dev/nexus
sudo chmod 755 /dev/nexus

sudo $openafs_dir/src/afsd/afsd
kinit $1
$openafs_dir/src/aklog/aklog -d
