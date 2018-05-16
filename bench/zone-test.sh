#!/bin/bash
num=1

while [ $num -lt 10 ]; do
  sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
  ~/iozone3-current/iozone -a -U 1 -g 32m -i 0 -i 1 -i 2 -e -c -r 4k
  let num+=1
done
