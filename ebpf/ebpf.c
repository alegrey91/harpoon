// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Alessio Greggi
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[25]);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// used to store the data received from the event
struct syscall_data {
	u32 syscall_id;
	u32 tracing_status;
};

// implement strncmp function
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
int enter_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracing_status = 1;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

// exit_function submit the value 2 to advice 
// the frontend app that the function finished its
// execution
SEC("uprobe/exit_function")
int exit_function(struct pt_regs *ctx) {
	struct syscall_data data = {};
	data.tracing_status = 2;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int start_trace(struct trace_event_raw_sys_enter* args) {
	struct syscall_data data = {};
	char comm[25];
	__u32 key_map = 0;

	bpf_get_current_comm(&comm, sizeof(comm));

	// lookup command passed as argument from Go application
	char *input_command = bpf_map_lookup_elem(&config_map, &key_map);
	if (!input_command) {
		return 1;
	}

	// skip if the command is not the one we want to trace
	if (__bpf_strncmp(comm, input_command, sizeof(comm)) != 0) {
		/*
			This is for debugging purposes, check output with:
			`sudo cat /sys/kernel/debug/tracing/trace_pipe`
		*/
		//bpf_printk("command doesn't match: %s / input command: %s\n", comm, input_command);
		return 1;
	}

	int id = (int)args->id;
	data.syscall_id = id;
	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}

/*
	Used to unlock some useful helpers
	More information here:
	https://github.com/nyrahul/ebpf-guide/blob/master/docs/gpl_license_ebpf.rst
*/
char __license[] SEC("license") = "GPL";