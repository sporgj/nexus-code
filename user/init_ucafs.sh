#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

repo_dir="/afs/xyz.vm/user/$1"

set -e
echo "Creating $repo_dir/{.afsx, .ucafs, sgx}"
rm -rf $repo_dir/.afsx $repo_dir/.ucafs $repo_dir/sgx/*
mkdir -p $repo_dir/.afsx $repo_dir/sgx

# make sure users can access the folders
fs sa -d $repo_dir/ -a system:anyuser write
fs sa -d $repo_dir/.afsx -a system:anyuser write
fs sa -d $repo_dir/sgx -a system:anyuser write

set -x
./admin_ucafs --init
