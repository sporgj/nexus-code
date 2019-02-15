# @author Judicael Briand Djoko <jbriand@cs.pitt.edu>
# A small script that interacts with the dropbox daemon

import os
import time
import socket


DROPBOX_STATUS_OK = 0
DROPBOX_STATUS_TIMEOUT = -1


# how often to query the socket
CHECK_INTERVAL_SECONDS = 0.0001

# the amount of time before the first "Syncing"
CHECK_TIMEOUT_SECONDS = 10

PARENT_DIR = os.path.expanduser("~")
DROPBOXD_PATH = "%s/.dropbox-dist/dropboxd" % PARENT_DIR

COMMAND_SOCKET_PATH = "%s/.dropbox/command_socket" % PARENT_DIR

GET_STATUS_CMD = "get_dropbox_status\ndone\n"


def is_dropbox_running():
    pidfile = os.path.expanduser("~/.dropbox/dropbox.pid")

    try:
        with open(pidfile, "r") as f:
            pid = int(f.read())
        with open("/proc/%d/cmdline" % pid, "r") as f:
            cmdline = f.read().lower()
    except:
        cmdline = ""

    return "dropbox" in cmdline


def poll_dropbox_status(timeout_secs=CHECK_TIMEOUT_SECONDS, elapsed_time={}):
    '''
    Loops and queryies the dropbox socket to get the status

    @param timeout_secs time to wait for first sync [default=CHECK_TIMEOUT_SECONDS]
    @return -1 on timeout
    '''
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # bind socket to file
    try:
        sock.connect(COMMAND_SOCKET_PATH)
    except socket.error as msg:
        print(msg)
        sys.exit(1)


    sock.send("get_dropbox_status\ndone\n".encode())

    first_time = time.monotonic()
    last_time = 0
    sync_time = 0

    while True:
        data = str(sock.recv(4096))

        if data.find("Up to date") != -1:
            if sync_time > 0:
                last_time = time.monotonic()
                # print("\nYAY!!! time = {:.6f}s".format(time.monotonic() - sync_time))
                break
        elif data.find("Syncing") != -1 and sync_time == 0:
            sync_time = time.monotonic()

        sock.send("get_dropbox_status\ndone\n".encode())

        time.sleep(CHECK_INTERVAL_SECONDS)

        if sync_time == 0 and (time.monotonic() - first_time) > timeout_secs:
            last_time = time.monotonic()
            elapsed_time['time'] = last_time - first_time
            sock.close()
            return DROPBOX_STATUS_TIMEOUT

    sock.close()
    elapsed_time['time'] = last_time - first_time
    return DROPBOX_STATUS_OK
