#!/usr/bin/python
import subprocess

arr = ['8k', '16k', '32k', '64k', '128k', '256k', '512k', '1M', '2M', '4M', '8M', '16M', '32M']
rounds = 5;

for s in arr:
    cmd = ['./gen_file', s, str(rounds)]
    if not subprocess.call(cmd) == 0:
        print("An error occured");
        break;
    print("\n");
