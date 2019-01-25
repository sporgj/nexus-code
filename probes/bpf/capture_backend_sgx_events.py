#!/usr/bin/python

from __future__ import print_function
from bcc import BPF, USDT
from collections import deque

import argparse
import atexit
import sys, os


parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", dest="pid", type=int, help="PID")
parser.add_argument("-c", "--comm", dest="comm", type=str, help="PROGRAM")

args = parser.parse_args()

if not args.pid and not args.comm:
    printf("USAGE: must provide pid or comm")
    parser.print_help()
    sys.exit(-1)


global_pid = args.pid
global_comm = args.comm



debug = 0

# load BPF program

src_dirpath = os.path.dirname(os.path.abspath(__file__))

src_filepath = os.path.join(src_dirpath, "./capture_sgx_backend.c")

with open(src_filepath, "r") as fp:
    bpf_text = '\n'.join(fp.readlines())

# enable USDT probe from given PID
u = USDT(pid=int(global_pid))
u.enable_probe(probe="ecall_start", fn_name="t_ecall_start")
u.enable_probe(probe="ecall_finish", fn_name="t_ecall_exit")
u.enable_probe(probe="iobuf_start", fn_name="t_iobuf_start")
u.enable_probe(probe="iobuf_finish", fn_name="t_iobuf_exit")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
g_event_labels = ['ecall', 'iobuf']

g_ecall_ops = {
        0x02: 'ECALL_FILLDIR' ,
        0x03: 'ECALL_CREATE'  ,
        0x04: 'ECALL_LOOKUP'  ,
        0x05: 'ECALL_STAT'  ,
        0x06: 'ECALL_REMOVE'  ,

        0x07: 'ECALL_HARDLINK',
        0x08: 'ECALL_SYMLINK' ,
        0x09: 'ECALL_READLINK' ,
        0x10: 'ECALL_RENAME'  ,

        0x12: 'ECALL_ENCRYPT' ,
        0x13: 'ECALL_DECRYPT'
}


g_ocall_ops = {
        0x101 : 'IOBUF_ALLOC'   ,
        0x102 : 'IOBUF_GET'     ,
        0x103 : 'IOBUF_PUT'     ,
        0x104 : 'IOBUF_FLUSH'   ,
        0x106 : 'IOBUF_NEW'     ,
        0x107 : 'IOBUF_DEL'     ,
        0x108 : 'IOBUF_HARDLINK',
        0x109 : 'IOBUF_RENAME'  ,
        0x110 : 'IOBUF_STAT'    ,

        0x111 : 'IOBUF_LOCK'    ,
        0x112 : 'IOBUF_UNLOCK'
};



total_event_count = dict([(ev_label, 0) for ev_label in g_event_labels])

total_event_duration = dict([(ev_label, 0) for ev_label in g_event_labels])

total_ops_count = {}
total_ops_duration = {}

total_number_of_events = 0

event_stack = deque([])


def get_op_str(ev_label, op_number_str):
    op_number = int(op_number_str)

    if ev_label == 'ecall':
        return g_ecall_ops[op_number]
    return g_ocall_ops[op_number]


def push_event_op(ev_label, ev_op, duration):
    ev_op_str = get_op_str(ev_label, ev_op)

    if ev_op_str not in total_ops_count:
        total_ops_count[ev_op_str] = 0

    if ev_op_str not in total_ops_duration:
        total_ops_duration[ev_op_str] = 0

    total_ops_count[ev_op_str] += 1
    total_ops_duration[ev_op_str] += duration

    total_event_count[ev_label] += 1
    total_event_duration[ev_label] += duration

    # print("%-18s %-16s" % (duration, ev_op_str))


def parse_event(msg, time):
    global event_stack

    (ev_type, ev_op) = msg.split(':')

    (ev_label, ev_status) = ev_type.split('_')

    if not ev_type.find('start') == -1:
        # push the event into the stack
        event_stack.append((ev_label, time))
    else:
        if len(event_stack) == 0:
            print("'%s' SKIPPED" % msg)
            return

        (start_ev_label, start_ev_time) = event_stack.pop()

        if not start_ev_label == ev_label:
            print(start_ev_label + ' != ' + ev_label + '... exiting')
            sys.exit(-1)

        duration = (float(time - start_ev_time))

        push_event_op(ev_label, ev_op, duration)


'''
b["events"].open_perf_buffer(parse_event)
while 1:
    b.perf_buffer_poll()
'''

def __real_event_name(key):
    return 'ecall+iobuf' if key == 'ecall' else key

def display():
    print()
    print('%d total events' % total_number_of_events)
    print('------------------------------------------------------')
    print("%-18s %-8s %-14s" % ("operation", "count", "duration (s)"))
    print('------------------------------------------------------')

    for key in sorted(total_event_count.keys()):
        print("%-18s %-8d %-14f" % (__real_event_name(key), total_event_count[key], total_event_duration[key]))

    print('------------------------------------------------------')
    for key in sorted(total_ops_count.keys()):
        print("%-18s %-8d %-14f" % (key, total_ops_count[key], total_ops_duration[key]))

atexit.register(display)

print('Recording... Press CTRL + C to stop')

# format output
try:
    while 1:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            print("value error")
            continue

        if (global_pid and int(global_pid) == pid) or (global_comm and global_comm == task):
            # print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
            total_number_of_events += 1

            parse_event(msg, ts)


except KeyboardInterrupt:
    print('closing now')
    pass
