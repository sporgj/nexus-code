#!/usr/bin/python3

'''
Runs the copy files benchmark
'''

import subprocess
import argparse
import string
import random
import time
import shutil
import os.path

from dropbox_watcher import poll_dropbox_status, DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT


global_rounds = 0
global_is_dropbox = False

STRING_CHOICES = string.ascii_uppercase + string.ascii_lowercase + string.digits


def __random_string():
    return ''.join(random.sample(STRING_CHOICES, k=7))


def __run_round(src_dir, dst_dir):
    global global_is_dropbox
    sync_time = {}
    time_lapse = time.monotonic()

    shutil.copytree(src_dir, dst_dir)

    if global_is_dropbox:
        if poll_dropbox_status(elapsed_time=sync_time) != DROPBOX_STATUS_OK:
            print(":( timeout on checking sync")

    time_lapse = time.monotonic() - time_lapse

    if global_is_dropbox:
        print("%-16f %-16f" % (time_lapse - sync_time['time'], time_lapse))
    else:
        print("%-16f" % (time_lapse))

    shutil.rmtree(dst_dir)

    # this ensures that the script pauses until the file removal is complete
    if global_is_dropbox:
        if poll_dropbox_status() != DROPBOX_STATUS_OK:
            print(":| we are going to pause (10s) for the sync")
            time.sleep(10)


def __run_test(src_dir, dst_dir):
    global global_rounds

    for r in range(global_rounds):
        __run_round(src_dir, dst_dir)


def __get_parser():
    parser = argparse.ArgumentParser(description="Runs the file copy benchmark")
    parser.add_argument("src_dir", type=str, help="the source directory")
    parser.add_argument("dst_dir", type=str, help="the destination directory")
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

    src_dir = os.path.abspath(args['src_dir'])
    dst_dir = os.path.abspath('/'.join([args['dst_dir'], __random_string()]))

    print("copyfiles: {} -> {}".format(src_dir, dst_dir))

    if global_is_dropbox:
        print("%-16s %-16s" % ("local_time(s)", "total_time(s)"))
    else:
        print("%-16s" % ("total time(s)"))

    __run_test(src_dir, dst_dir)


if __name__ == "__main__":
    command_line_runner()
