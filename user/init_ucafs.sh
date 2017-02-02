#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

set -x

repo_dir="/afs/xyz.vm/user/$1"
set -e
echo "clearing $repo_dir/{.afsx, .ucafs, sgx}"
rm -rf $repo_dir/.afsx $repo_dir/.ucafs $repo_dir/sgx/*
mkdir -p $repo_dir/.afsx $repo_dir/sgx
fs sa -d $repo_dir/.afsx -a system:anyuser write
./admin_ucafs --init
