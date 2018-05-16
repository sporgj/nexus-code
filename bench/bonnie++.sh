#!/bin/bash
num=1

while [ $num -lt 9 ]; do
  sudo bash -c "echo 3 > /proc/sys/vm/drop_caches"
  sudo bonnie++ -u briand -q -x 10 -s 0 -r 0 -n $num
  let num*=2
done
