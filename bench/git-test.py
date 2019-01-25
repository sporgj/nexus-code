#!/usr/bin/python3
import argparse
import subprocess
import time

parser = argparse.ArgumentParser(description="Clone (redis, julia, node) from bonino")
parser.add_argument('rounds', nargs='?', default=10)
args = parser.parse_args()

# parse the arguments
gbl_rounds = int(args.rounds)

base_url = 'git@bonino.cs.pitt.edu'
repos = ['redis.git', 'julia.git', 'node.git']

for rp in repos:
    url = ':'.join([base_url, rp])
    folder = rp.split('.')[0];

    git_cmd = ['git', 'clone', '-q', url]
    rm_cmd = ['rm', '-rf', folder]

    print('Cloning {:} -> {:}'.format(url, folder))

    for i in range(gbl_rounds):
        t1 = time.monotonic()
        subprocess.call(git_cmd)
        print('{:.6f}s'.format(time.monotonic() - t1))
        subprocess.call(rm_cmd)
