#!/bin/bash

for i in `seq 1 5`
do
  echo "------------------- Step $i -------------------"
  time wget https://nodejs.org/dist/v6.9.1/node-v6.9.1.tar.gz
  time tar -xf node-v6.9.1.tar.gz
  time rm -rf node-v6.9.1
  time rm node-v6.9.1.tar.gz
  echo "-----------------------------------------------"
done
