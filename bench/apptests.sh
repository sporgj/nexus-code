#!/bin/bash
# exit on error
set -e

btime='/usr/bin/time -f %e'
nodejs_url='https://github.com/v8/v8/archive/6.0.261.tar.gz' 
sintel_url='/home/briand/Sintel.2010.720p.mkv'
nodejs_fname='v8-6.0.261'
test_fldr='fake_dir'

echo 'wget1, tar, du1, grep1, wget2, ffmpeg'

for i in `seq 1 7`
do
  # remove everything
  $(rm -rf ./*)

  # wget
  wget1=$(${btime} wget -q ${nodejs_url} -O nodejs.tar.gz)

  # extract archive
  tar=$(${btime} tar -xf nodejs.tar.gz)

  # calculate disk usage
  du1=$(${btime} du -ch ${nodejs_fname} > /dev/null)

  # find 'javascript'
  grep1=$(${btime} find . -type f -exec grep -q -i 'javascript' '{}' \;)

  # download the movie
  wget2=$(${btime} cp ${sintel_url} sintel.mkv)

  # generate jpegs
  ffmpeg=$(${btime} ffmpeg -i sintel.mkv -v -8 -vf fps=1/5 img%03d.jpg)
  echo ${wget1}, ${tar}, ${du1}, ${grep1}, ${wget2}, ${ffmpeg}
done

rm -rf ./*
