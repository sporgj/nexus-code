#!/usr/bin/python3

'''
Runs the file I/O benchmark

@author Judicael Briand Djoko <jbriand@cs.pitt.edu>
'''

import subprocess, argparse, os, time, random
from dropbox_watcher import poll_dropbox_status,\
        DROPBOX_STATUS_OK, DROPBOX_STATUS_TIMEOUT


MULTIPLIERS = {
    'g': (1 << 30),
    'G': (1 << 30),
    'm': (1 << 20),
    'M': (1 << 20),
    'k': (1 << 10),
    'K': (1 << 10),
}


def filesize_str_to_int(filesize_str):
    number_str, unit_str = filesize_str[:-1], filesize_str[-1:]

    if unit_str.isdigit() or len(filesize_str) == 1:
        return int(filesize_str, 10)

    return int(number_str, 10) * (MULTIPLIERS.get(unit_str, 1))


def human_size(num: int) -> str:
    '''
    https://stackoverflow.com/a/53566690
    '''
    base = 1
    for unit in ['B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']:
        n = num / base
        if n < 9.95 and unit != 'B':
            # Less than 10 then keep 1 decimal place
            value = "{:.1f}{}".format(n, unit)
            return value
        if round(n) < 1000:
            # Less than 4 digits so use this
            value = "{}{}".format(round(n), unit)
            return value
        base *= 1024
    value = "{}{}".format(round(n), unit)
    return value


def run_test(filesize, rounds, has_dropbox):
    for i in range(rounds):
        time_lapse = time.monotonic()
        sync_time = 0

        filename = "testfile-%d-%d" % (i, random.randint(1, 1e9))

        with open(filename, "wb") as f:
            f.write(os.urandom(filesize))

        if has_dropbox:
            status, sync_time = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":( timeout on checking sync")

        time_lapse = time.monotonic() - time_lapse
        io_time = time_lapse - sync_time

        if has_dropbox:
            print("%-10s %-10f %-10f %-10f" %
                  (human_size(filesize), io_time, sync_time, time_lapse))
        else:
            print("%-10s %-10f" % (human_size(filesize), time_lapse))

        os.remove(filename)

        # this ensures that the script pauses until the file removal is complete
        if has_dropbox:
            status, _ = poll_dropbox_status()
            if status != DROPBOX_STATUS_OK:
                print(":| we are going to pause (10s) for the sync")
                time.sleep(10)


def __get_parser():
    parser = argparse.ArgumentParser(description="Runs the raw I/O benchmark")
    parser.add_argument("filesizes", type=str,
                        help="file sizes (units: k,m,g). Comma-seperate for \
                                different file sizes")
    parser.add_argument("-r", "--rounds", dest="rounds", default=1, type=int,
                        help="Number of rounds")
    parser.add_argument("-d", "--dropbox", dest="dropbox", action="store_true",
                        help="Whether we check dropbox")
    return parser


def command_line_runner():
    parser = __get_parser()
    args = vars(parser.parse_args())

    args_rounds = args['rounds']
    args_dropbox = args['dropbox']

    # parse the string array
    filesizes_string_array = args['filesizes'].split(',')

    if not filesizes_string_array:
        print("specified file sizes are incorrect")
        sys.exit(-1)


    filesizes_int_array = [filesize_str_to_int(fz) for fz in filesizes_string_array]

    if args_dropbox:
        print("%-10s %-10s %-10s %-10s" % ("filesize", "io_time", "sync_time", "elapsed(s)"))
    else:
        print("%-10s %-10s" % ("filesize", "time_lapse(s)"))

    for fz in filesizes_int_array:
        run_test(fz, args_rounds, args_dropbox)


if __name__ == "__main__":
    command_line_runner()
