#!/bin/bash

files=$1
if [ -z "$files" ]
then
  echo "run: $0 number_of_files"
  exit
fi

for i in `seq 1 5`;
do
  sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
  echo '------------------------------------'
  echo             $i $files              
  echo '------------------------------------'

  python3 dir_create.py $i $files
  echo
done
