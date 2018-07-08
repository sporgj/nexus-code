#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct key_t {
    char c[80];
}

BPF_HASH(counts, struct key_t);

int trace_req_count(struct pt_regs * ctx)
{
    u64 zero, *val = NULL;

    if (!PT_REGS_PARM1(ctx)) {
        return 0;
    }

    struct key_t key = {};
    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));

    val = counts.lookup_or_init(&key, &zero);
    (*val)++;

    return 0;
}

int trace_req_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;
    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0;	// missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    FACTOR
    // store as histogram
    int index = bpf_log2l(delta);
    u64 *leaf = dist.lookup(&index);
    if (leaf) (*leaf)++;
    start.delete(&req);
    return 0;
}
