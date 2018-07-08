#!/usr/bin/python3

from bcc import BPF
from time import sleep

b = BPF(src_file="ecalls_tracing_src.c")

b.attach_probe('u:backend_sgx:ecall_start', fn_name='trace_req_count')

# print output
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
