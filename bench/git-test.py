#!/usr/bin/python3

import argparse
import subprocess
import time
from dropbox_watcher import poll_dropbox_status, DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT

from nexus_commander import enable_batchmode, disable_batchmode

global_rounds = 1
global_is_dropbox = False
global_commander_path = None

base_url = 'git@bonino.cs.pitt.edu'
global_repos = ['redis.git', 'julia.git', 'node.git']


def __clone_repository(url, folder):
    global global_is_dropbox
    global global_commander_path

    sync_time = 0
    clone_time = 0
    time_lapse = time.monotonic()

    git_cmd = ['git', 'clone', '-q', url]
    rm_cmd = ['rm', '-rf', folder]

    try:
        if global_commander_path:
            enable_batchmode(global_commander_path)

        ret = subprocess.check_output(git_cmd)

        if global_commander_path:
            disable_batchmode(global_commander_path)

        if global_is_dropbox:
            status, sync_time = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":( timeout on checking sync")

        subprocess.call(rm_cmd)
    except subprocess.CalledProcessError as e:
        subprocess.call(rm_cmd)
        pass

    time_lapse = time.monotonic() - time_lapse
    clone_time = time_lapse - sync_time

    if global_is_dropbox:
        print("%-16f %-16f %-16f" % (clone_time, sync_time, time_lapse))

        # this ensures that the script pauses until the file removal is complete
        status, _ = poll_dropbox_status()
        if status != DROPBOX_STATUS_OK:
            print(":| we are going to pause (10s) for the sync")
            time.sleep(10)
    else:
        print("%-16f" % (time_lapse))


def __run_test(repos):
    global global_rounds

    for rp in repos:
        url = ':'.join([base_url, rp])
        folder = rp.split('.')[0];

        print('Cloning {:} -> {:}'.format(url, folder))

        for i in range(global_rounds):
            __clone_repository(url, folder)


def __get_parser():
    global global_repos

    parser = argparse.ArgumentParser(description="Clone (redis, julia, node) from bonino")
    parser.add_argument('repo', nargs='*', default=global_repos, help='which repos to clone')
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

    for repo in args['repo']:
        if not repo in global_repos:
            raise Exception('`%s` is not a known repositor' % repo)

    __run_test(args['repo'])


if __name__ == "__main__":
    command_line_runner()
