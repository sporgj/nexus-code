#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

int
trace_sgx_calls(struct pt_regs * ctx)
{
    bpf_trace_printk("entry/exit");

    return 0;
}
