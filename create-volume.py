#!/usr/bin/python
from __future__ import print_function
import json, os, argparse, sys, commands, subprocess

parser = argparse.ArgumentParser(description="Creating a NeXUS volume")
parser.add_argument("config", type=str, help="the config.json file")
args = parser.parse_args()

gbl_config = args.config

if not os.access(gbl_config, os.R_OK):
    sys.exit(-1)

config = {}
with open(gbl_config, "r") as fp:
    config = json.load(fp)

# get the elements
pubkey_path = config['publickey']
privkey_path = config['privatekey']
metadata_path = config['metadata_dir']
datafolder_path = config['data_dir']
volkey_path = config['volume_key']

print('-------------------------------------------------------------')
print('\t      volume key:', volkey_path)
print('\t      public key:', pubkey_path)
print('\t     private key:', privkey_path)
print('\t   metadata path:', metadata_path)
print('\t datafolder path:', datafolder_path)

m_path = os.path.abspath(metadata_path)
d_path = os.path.abspath(datafolder_path)

print('-------------------------------------------------------------')
print('Clearing:', m_path)
subprocess.call("mkdir -p " + m_path, shell=True)
status = subprocess.call("rm -rf " + m_path + "/*", shell=True)

print('Clearing:', d_path)
subprocess.call("mkdir -p " + d_path, shell=True)
status = subprocess.call("rm -rf " + d_path + "/*", shell=True)
print('-------------------------------------------------------------')


status = subprocess.call(["./nx-create-volume", pubkey_path, privkey_path,
    metadata_path, volkey_path])
if not status == 0:
    sys.exit(-1)
