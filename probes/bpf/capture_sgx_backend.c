#include <uapi/linux/ptrace.h>

int
t_ecall_enter(struct pt_regs * ctx)
{
    int op = 0;

    bpf_usdt_readarg(1, ctx, &op);

    bpf_trace_printk("ecall_start:%d\n", op);
    return 0;
};

int
t_ecall_exit(struct pt_regs * ctx)
{
    int op = 0;

    bpf_usdt_readarg(1, ctx, &op);

    bpf_trace_printk("ecall_finish:%d\n", op);
    return 0;
};

int
t_iobuf_enter(struct pt_regs * ctx)
{
    int op = 0;

    bpf_usdt_readarg(1, ctx, &op);

    bpf_trace_printk("iobuf_start:%d\n", op);
    return 0;
};

int
t_iobuf_exit(struct pt_regs * ctx)
{
    int op = 0;

    bpf_usdt_readarg(1, ctx, &op);

    bpf_trace_printk("iobuf_finish:%d\n", op);
    return 0;
};
