#!/usr/bin/python3

import os
import argparse
import subprocess
import time
from dropbox_watcher import poll_dropbox_status, DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT

global_rounds = 1
global_is_dropbox = False


def __make_command():
    global global_is_dropbox

    sync_time = 0
    make_time = 0
    time_lapse = time.monotonic()

    make_cmd = ['make', '-j8', '-s']  # TODO use $(nprocs)
    clean_cmd = ['make', '-s', 'clean']

    try:
        subprocess.check_output(make_cmd, stderr=subprocess.STDOUT)

        if global_is_dropbox:
            status, sync_time = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":( timeout on checking sync")

        time_lapse = time.monotonic() - time_lapse

        subprocess.call(clean_cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        subprocess.call(clean_cmd, stderr=subprocess.STDOUT)

    make_time = time_lapse - sync_time

    if global_is_dropbox:
        print("%-16f %-16f %-16f" % (make_time, sync_time, time_lapse))

        # this ensures that the script pauses until the file removal is complete
        status, _ = poll_dropbox_status()
        if status != DROPBOX_STATUS_OK:
            print(":| we are going to pause (10s) for the sync")
            time.sleep(10)
    else:
        print("%-16f" % (time_lapse))


def make_test_main():
    global global_rounds
    global global_is_dropbox

    if global_is_dropbox:
        print("%-16s %-16s" % ("Sync time", "Elapsed time"))
    else:
        print("%-16s" % ("Elapsed time"))

    for i in range(global_rounds):
        __make_command()


def __get_parser():
    parser = argparse.ArgumentParser(description="Time make command in directory")
    parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int,
                        help="Number of rounds")
    parser.add_argument("-d", "--dropbox", dest="dropbox", action="store_true",
                        help="Whether we check dropbox")

    return parser


def command_line_runner():
    global global_rounds
    global global_is_dropbox

    parser = __get_parser()
    args = vars(parser.parse_args())

    global_rounds = args['rounds']
    global_is_dropbox = args['dropbox']

    make_test_main()


if __name__ == "__main__":
    command_line_runner()


