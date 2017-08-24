#!/usr/bin/python3
import os, subprocess, time

command = 'git am {:}'

# the total time for the execution
total_time = 0

i = 0
for dirname, subdirs, filenames in os.walk('/home/briand/nano-patchset'):
    filenames.sort()
    for fname in filenames:
        fpath = os.path.join(dirname, fname)
        cmd = ['git', 'am', '--whitespace=nowarn', fpath]

        # time the apply patch
        # t1 = time.monotonic()
        code = subprocess.check_call(cmd)
        if code != 0:
            print('FAIL: ' + ''.join(cmd))
            break
        # t1 = time.monotonic() - t1
        # total_time += t1

        # time the push
        cmd = ['git', 'push', '-q', 'origin', 'master']
        t1 = time.monotonic()
        code = subprocess.check_call(cmd)
        if code != 0:
            print('FAIL: ' + ''.join(cmd))
            break
        t1 = time.monotonic() - t1
        total_time += t1

        i += 1
        if i == 150:
            break

    break

print('Patches applied: {:}, total_time: {:}'.format(i, total_time))
