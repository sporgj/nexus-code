#!/bin/bash
if [ "$#" -lt 1 ]; then
  echo "usage: $0 username"
  exit 1
fi

repo_dir="$(pwd)/repo/$1"

echo $repo_dir > profile/repo.datum

set -e
echo "Creating $repo_dir/{.afsx, sgx}"
rm -rf $repo_dir/.afsx $repo_dir/sgx/*
mkdir -p $repo_dir/.afsx $repo_dir/sgx

set -x
../admin_ucafs --init
