#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_TABLE("array", int, u64, dist, 64);
BPF_HASH(start, struct request *);

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
	u64 ts = bpf_ktime_get_ns();
	start.update(&req, &ts);
	return 0;
}

// output
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
