#!/bin/bash

openafs_dir=$HOME/nexus/openafs/src

set -e
set -x
sudo ln -sf $HOME/nexus/start-afs.sh $HOME/start-afs.sh
sudo ln -sf $openafs_dir/aklog/aklog /usr/local/bin/aklog
sudo ln -sf $openafs_dir/afsd/afsd /usr/local/bin/afsd
sudo ln -sf $openafs_dir/venus/fs /usr/local/bin/fs
