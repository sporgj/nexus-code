#!/usr/bin/python
import subprocess

arr = ['1M', '4M', '16M', '64M']
rounds = 10;

for s in arr:
    cmd = ['./gen_file', s, str(rounds)]
    if not subprocess.call(cmd) == 0:
        print("An error occured");
        break;
    print("\n");
