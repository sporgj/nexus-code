#!/usr/bin/python3

'''
This file runs the create/delete benchmark

@author Judicael Briand Djoko <jbriand@cs.pitt.edu>
'''

import os, argparse, sys, time, random;
from pathlib import Path;

import dropbox_watcher



def create_files(filelist, has_dropbox):
    sync_time = 0
    t1 = time.monotonic()

    for fpath in filelist:
        Path(fpath).touch()

    if has_dropbox:
        status, sync_time = dropbox_watcher.poll_dropbox_status()
        if status != dropbox_watcher.DROPBOX_STATUS_OK:
            print("ERROR:, dropbox status error on create")

    create_time = time.monotonic() - t1

    return (create_time, sync_time)


def remove_files(filelist, has_dropbox):
    sync_time = 0
    t1 = time.monotonic()

    for fpath in filelist:
        os.remove(fpath)

    if has_dropbox:
        status, sync_time = dropbox_watcher.poll_dropbox_status()
        if status != dropbox_watcher.DROPBOX_STATUS_OK:
            print("ERROR:, dropbox status error on create")

    remove_time = time.monotonic() - t1

    return (remove_time, sync_time)


def run(filecount, rounds, randomize, has_dropbox):
    # Create the home directory
    testdir = 'test.' + str(os.getpid())
    os.mkdir(testdir)

    if has_dropbox:
        print("%-8s %-10s %-10s %-10s %-10s" %
               ("count", "create(s)", "delete(s)", "sync(s)", "elapsed(s)"))
    else:
        print("%-8s %-10s %-10s %-10s" % ("count", "create(s)", "delete(s)", "elapsed(s)"))

    for i in range(rounds):
        # generate the list of all files
        filelist = [testdir+'/file-'+str(i) for i in range(filecount)]

        time_lapse = time.monotonic()

        # create the files
        (create_total, create_sync) = create_files(filelist, has_dropbox)

        if randomize:
            random.shuffle(filelist)

        # remove the files
        (remove_total, remove_sync) = remove_files(filelist, has_dropbox)

        time_lapse = time.monotonic() - time_lapse
        time_sync = create_sync + remove_sync

        del(filelist)

        create_time = create_total - create_sync
        remove_time = remove_total - remove_sync

        if has_dropbox:
            print("%-8d %-10f %-10f %-10f %-10f" %
                  (filecount, create_time, remove_time, time_sync, time_lapse))
        else:
            print("%-8d %-10f %-10f %-10f" %
                  (filecount, create_time, remove_time, time_lapse))

    os.rmdir(testdir)


def __get_parser():
    parser = argparse.ArgumentParser(
            description="Create files in a flat directory in seq/rand order")
    parser.add_argument("file_count", type=int, help="Number of files")
    parser.add_argument("--shuffle", dest="randomize", action="store_true",
                        help="Randomize the create/delete")
    parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int,
                        help="Number of rounds")
    parser.add_argument("-d", "--dropbox", dest="dropbox", action="store_true",
                        help="Whether we check dropbox")
    return parser


def command_line_runner():
    parser = __get_parser()
    args = parser.parse_args()

    run(args.file_count, args.rounds, args.randomize, args.dropbox)


if __name__ == '__main__':
    command_line_runner()
