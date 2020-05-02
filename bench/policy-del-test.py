#!/usr/bin/python3

import os
import argparse
import subprocess
import time
from dropbox_watcher import poll_dropbox_status, DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT

global_is_dropbox = False


def run_main(volume_path):
    global global_is_dropbox

    time_lapse = time.monotonic()
    sync_time = 0;

    _cmd = ['../shell/nexus_shell', 'cmd', volume_path, 'abac_policy_pop']

    try:
        ret = subprocess.check_output(_cmd)

        if global_is_dropbox:
            status, sync_time = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":( timeout on checking sync")

        time_lapse = time.monotonic() - time_lapse
    except subprocess.CalledProcessError as e:
        print(e)
        return

    if global_is_dropbox:
        local_time = time_lapse - sync_time
        print("%-16s %-16s %-16s" % ("Local time", "Sync time", "Elapsed time"))
        print("%-16f %-16f %-16f" % (local_time, sync_time, time_lapse))
    else:
        print("%-16s" % ("Elapsed time"))
        print("%-16f" % (time_lapse))


def __get_parser():
    parser = argparse.ArgumentParser(description="Delete a random policy")
    parser.add_argument('volume_path', type=str, help='path to the volume')
    parser.add_argument("-d", "--dropbox", dest="dropbox", action="store_true",
                        help="Whether we check dropbox")

    return parser


def command_line_runner():
    global global_is_dropbox

    parser = __get_parser()
    args = vars(parser.parse_args())

    global_is_dropbox = args['dropbox']

    run_main(args['volume_path'])


if __name__ == "__main__":
    command_line_runner()
