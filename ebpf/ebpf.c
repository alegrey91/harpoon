#include <uapi/linux/ptrace.h>
#include <linux/string.h>
#include <linux/tracepoint.h>

BPF_PERF_OUTPUT(events);

// data_t used to store the data received from the event
struct syscall_data {
	// the syscall number
	u32 syscall_id;
	// tracing status (1 start, 2 stop)
	u32 tracingStatus;
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
inline int enter_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracingStatus = 1;
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}

// exit_function submit the value 2 to advice 
// the frontend app that the function finished its
// execution
inline int exit_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracingStatus = 2;
	events.perf_submit(ctx, &data, sizeof(data));
	return 0;
}

int start_trace(struct tracepoint__raw_syscalls__sys_enter* args) {
	struct syscall_data data = {};

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	// skip if the command is not the one we want to trace
	if (__bpf_strncmp(comm, "$CMD", sizeof(comm)) != 0) {
		bpf_trace_printk("command doesn't match: %s\n", comm);
		return 1;
	}

	int id = (int)args->id;
	data.syscall_id = id;
	events.perf_submit(args, &data, sizeof(data));
	return 0;
}

