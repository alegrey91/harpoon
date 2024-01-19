//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/string.h>
#include <bpf/bpf_tracing.h>

//BPF_PERF_OUTPUT(events);
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// data_t used to store the data received from the event
struct syscall_data {
	// the syscall number
	__u32 syscall_id;
	// tracing status (1 start, 2 stop)
	__u32 tracingStatus;
};

struct sys_enter_info {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long id;
    unsigned long args[6];
};

// imlement strncmp function
// https://sysdig.com/blog/ebpf-offensive-capabilities/
static __always_inline __u64
__bpf_strncmp(const void *x, const void *y, __u64 len) {
	for (int i = 0; i < len; i++) {
		if (((char *)x)[i] != ((char *)y)[i]) {
			return ((char *)x)[i] - ((char *)y)[i];
		}
		else if (((char *)x)[i] == '\0') {
			return 0;
		}
	}
	return 0;
}

// enter_function submit the value 1 to advice 
// the frontend app that the function started its
// execution
SEC("uprobe/enter_function")
inline int uprobe_enter_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracingStatus = 1;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

// exit_function submit the value 2 to advice 
// the frontend app that the function finished its
// execution
SEC("uprobe/exit_function")
inline int uprobe_exit_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracingStatus = 2;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int tracepoint_raw_sys_enter(struct sys_enter_info* ctx) {
	struct syscall_data data = {};

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	// skip if the command is not the one we want to trace
	if (__bpf_strncmp(comm, "$CMD", sizeof(comm)) != 0) {
		//bpf_trace_printk("command doesn't match: %s\n", comm);
		return 1;
	}

	int id = (int)ctx->id;
	data.syscall_id = id;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
