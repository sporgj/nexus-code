#!/usr/bin/env python

from __future__ import print_function

import argparse
import fnmatch
import os
import sys

from bcc import BPF, USDT


if len(sys.argv) < 2:
    print("Please provide PID")
    exit()
pid = sys.argv[1]
debug = 0


u = USDT(pid=int(pid))
u.enable_probe(probe="sgx_enter", fn_name="trace_sgx_calls")
u.enable_probe(probe="sgx_exit", fn_name="trace_sgx_calls")

b = BPF(src_file='capture_backend_events_src.c', usdt_contexts=[u])

# b.attach_uprobe(name='nexus-afs', sym='sgx_enter', fn_name='trace_sgx_calls')
# b.attach_uprobe('u:nexus_backend_sgx:sgx_exit', fn_name='trace_sgx_calls')

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "QUERY"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        print('problem')
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
