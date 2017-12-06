#!/usr/bin/python
from __future__ import print_function
import json, os, argparse, sys, commands, subprocess

parser = argparse.ArgumentParser(description="Creating a NeXUS volume")
parser.add_argument("--cmd", action="store_true", help="Don't run libnexus, just print the command")
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
datadir_path = config['data_dir']
volkey_path = config['volume_key']

print("Starting NeXUS")
print('\t      public key:', pubkey_path)
print('\t     private key:', privkey_path)
print('\t   metadata path:', metadata_path)
print('\t    datadir path:', datadir_path)
print('\t      volume key:', volkey_path)

m_fpath = os.path.abspath(metadata_path)

command = ["./nexus", "--pub_key", pubkey_path,
    "--prv_key", privkey_path, "--metadata_dir", metadata_path,
    "--data_dir", datadir_path, "--vol_key", volkey_path];

print('-------------------------------------------------------------')
if args.cmd:
    print(' '.join(command))
    sys.exit(0)

status = subprocess.call(command)
if not status == 0:
    sys.exit(-1)
