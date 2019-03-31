import os
import time
import socket

CHECK_INTERVAL_SECONDS = 0.01

COMMANDER_ERROR = -1
COMMANDER_SUCCESS = 0


def enable_batchmode(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        sock.connect(path)
    except socket.error as msg:
        print(msg)
        return COMMANDER_ERROR

    sock.send("batch_on".encode())

    start_time = time.monotonic()

    while True:
        data = str(sock.recv(1024))

        if data.find("OK"):
            break;

        time.sleep(CHECK_INTERVAL_SECONDS)

    sock.close()
    elapsed_time = time.monotonic() - start_time
    return (COMMANDER_SUCCESS, elapsed_time)


def disable_batchmode(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        sock.connect(path)
    except socket.error as msg:
        print(msg)
        return COMMANDER_ERROR

    sock.send("batch_off".encode())

    start_time = time.monotonic()

    while True:
        data = str(sock.recv(1024))

        if data.find("OK"):
            break;

        time.sleep(CHECK_INTERVAL_SECONDS)

    sock.close()
    elapsed_time = time.monotonic() - start_time
    return (COMMANDER_SUCCESS, elapsed_time)
