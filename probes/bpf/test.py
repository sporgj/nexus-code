#!/usr/bin/python
#
# nodejs_http_server    Basic example of node.js USDT tracing.
#                       For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: nodejs_http_server PID
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
import atexit
import sys, os
from collections import deque

if len(sys.argv) < 2:
    print("USAGE: ./test.py PID")
    exit()
prog_pid = sys.argv[1]
debug = 0

# load BPF program

src_dirpath = os.path.dirname(os.path.abspath(__file__))

src_filepath = os.path.join(src_dirpath, "./capture_sgx_backend.c")

with open(src_filepath, "r") as fp:
    bpf_text = '\n'.join(fp.readlines())

# enable USDT probe from given PID
u = USDT(pid=int(prog_pid))
u.enable_probe(probe="ecall_start", fn_name="t_ecall_enter")
u.enable_probe(probe="ecall_finish", fn_name="t_ecall_exit")
u.enable_probe(probe="iobuf_start", fn_name="t_iobuf_enter")
u.enable_probe(probe="iobuf_finish", fn_name="t_iobuf_exit")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])

# header
g_event_labels = ['ecall', 'iobuf']

g_ecall_ops = {
        2: 'ECALL_FILLDIR' ,
        3: 'ECALL_CREATE'  ,
        4: 'ECALL_LOOKUP'  ,
        5: 'ECALL_REMOVE'  ,
        6: 'ECALL_HARDLINK',
        7: 'ECALL_SYMLINK' ,
        8: 'ECALL_RENAME'  ,
        9: 'ECALL_STOREACL',
        10: 'ECALL_ENCRYPT' ,
        11: 'ECALL_DECRYPT'
}


g_ocall_ops = {
        0x101 : 'IOBUF_ALLOC'   ,
        0x102 : 'IOBUF_GET'     ,
        0x103 : 'IOBUF_PUT'     ,
        0x104 : 'IOBUF_FLUSH'   ,
        0x105 : 'IOBUF_LOCK'    ,
        0x106 : 'IOBUF_NEW'     ,
        0x107 : 'IOBUF_DEL'     ,
        0x108 : 'IOBUF_HARDLINK',
        0x109 : 'IOBUF_RENAME'  ,
        0x110 : 'IOBUF_STAT'
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

def display():
    print()
    print('%d total events' % total_number_of_events)
    print('------------------------------------------------------')
    print("%-18s %-8s %-14s" % ("operation", "count", "duration (s)"))
    print('------------------------------------------------------')

    for key in sorted(total_event_count.keys()):
        print("%-18s %-8d %-14f" % (key, total_event_count[key], total_event_duration[key]))

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

        if int(prog_pid) == pid:
            # print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
            total_number_of_events += 1

            parse_event(msg, ts)

except KeyboardInterrupt:
    print('closing now')
    pass
