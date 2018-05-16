#!/bin/bash
start=32

name=$1
if [ -z "$name" ]
then
  echo "$0 username"
  exit
fi

for i in `seq 1 6`
do
  echo "--------------- $start MB ----------------"
  sudo bonnie++ -u $name -s $start -r $(($start/2)) -q -x 10 -n 0
  let start=start*2
done
