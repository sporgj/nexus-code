#!/usr/bin/python3

import os
import argparse
import subprocess
import time
from dropbox_watcher import poll_dropbox_status, DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT

from nexus_commander import enable_batchmode, disable_batchmode

global_rounds = 1
global_is_dropbox = False
global_commander_path = None


def __extract_archive(archive_path, dest_folder):
    global global_is_dropbox

    batch_time = 0
    sync_time = 0
    xtract_time = 0
    time_lapse = time.monotonic()

    tarx_cmd = ['tar', '-xf', archive_path, '-C', dest_folder]
    rm_cmd = ['rm' , '-rf', dest_folder]

    os.mkdir(dest_folder)

    try:
        if global_commander_path:
            enable_batchmode(global_commander_path)

        ret = subprocess.check_output(tarx_cmd)

        batch_time = time.monotonic() - time_lapse

        if global_commander_path:
            disable_batchmode(global_commander_path)

        if global_is_dropbox:
            status, sync_time = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":( timeout on checking sync")

        time_lapse = time.monotonic() - time_lapse

        # subprocess.call(rm_cmd)
    except subprocess.CalledProcessError as e:
        # subprocess.call(rm_cmd)
        pass

    xtract_time = time_lapse - sync_time

    if global_commander_path:
        print('%-16f' % (batch_time), end='')

    if global_is_dropbox:
        print("%-16f %-16f %-16f" % (xtract_time, sync_time, time_lapse))

        # this ensures that the script pauses until the file removal is complete
        status, _ = poll_dropbox_status()
        if status != DROPBOX_STATUS_OK:
            print(":| we are going to pause (10s) for the sync")
            time.sleep(10)
    else:
        print("%-16f" % (time_lapse))


def tarx_main(archive_path, dest_folder):
    global global_rounds
    global global_is_dropbox

    testdir = ('{}/tarx-{}'.format(dest_folder, str(os.getpid())))

    if global_commander_path:
        print('%-16s' % ("Batch time"), end='')

    if global_is_dropbox:
        print("%-16s %-16s" % ("Sync time", "Elapsed time"))
    else:
        print("%-16s" % ("Elapsed time"))

    for i in range(global_rounds):
        __extract_archive(archive_path, testdir)


def __get_parser():
    global global_repos

    parser = argparse.ArgumentParser(description="Clone (redis, julia, node) from bonino")
    parser.add_argument('archive_filepath', type=str, help='file path to the tar.gz archive')
    parser.add_argument('dest_dirpath', type=str, help='which repos to clone')
    parser.add_argument('-c', "--commander", type=str, dest="commander_path", help="path to commander socket")
    parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int,
                        help="Number of rounds")
    parser.add_argument("-d", "--dropbox", dest="dropbox", action="store_true",
                        help="Whether we check dropbox")

    return parser


def command_line_runner():
    global global_rounds
    global global_is_dropbox
    global global_commander_path

    parser = __get_parser()
    args = vars(parser.parse_args())

    global_rounds = args['rounds']
    global_is_dropbox = args['dropbox']
    global_commander_path = args.get('commander_path', None)

    tarx_main(args['archive_filepath'], args['dest_dirpath'])


if __name__ == "__main__":
    command_line_runner()

