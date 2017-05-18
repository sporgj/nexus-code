#!/bin/bash
# exit on error
set -e

btime='/usr/bin/time -f %e'
nodejs_url='https://nodejs.org/dist/v7.10.0/node-v7.10.0-linux-x64.tar.xz' 
sintel_url='http://ftp.nluug.nl/pub/graphics/blender/demo/movies/Sintel.2010.720p.mkv'
nodejs_fname='node-v7.10.0-linux-x64'
test_fldr='fake_dir'

# remove everything
$(rm -rf ./*)
echo 'wget1, tar, du1, grep1, wget2, ffmpeg'

# wget
wget1=$(${btime} wget -q ${nodejs_url} -O nodejs.tar.gz)

# extract archive
tar=$(${btime} tar -xf nodejs.tar.gz)

# calculate disk usage
du1=$(${btime} du -h ${nodejs_fname})

# find 'javascript'
grep1=$(${btime} find . -type f -exec grep -q -i 'javascript' '{}' \;)

# download the movie
wget2=$(${btime} wget -q ${sintel_url} -O sintel.mkv)

# generate jpegs
ffmpeg=$(${btime} ffmpeg -i sintel.mkv -vf fps 1/5 img%03d.jpg)

echo ${wget1}, ${tar}, ${du1}, ${grep1}, ${wget2}, ${ffmpeg}, lol
