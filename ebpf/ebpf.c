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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tracing);
} tracing_status SEC(".maps");

// used to store the data received from the event
struct syscall_data {
	u32 syscall_id;
};

struct tracing {
	u32 status;
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
	struct tracing tc = {};
	__u32 key_map_trace = 0;
	tc.status = 1;
	bpf_map_update_elem(&tracing_status, &key_map_trace, &tc, 0);
	bpf_printk("enter function");
	return 0;
}

// exit_function submit the value 2 to advice 
// the frontend app that the function finished its
// execution
SEC("uprobe/exit_function")
int exit_function(struct pt_regs *ctx) {
	struct tracing tc = {};
	__u32 key_map_trace = 0;
	tc.status = 2;
	bpf_map_update_elem(&tracing_status, &key_map_trace, &tc, 0);
	bpf_printk("exit function");
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter* args) {
	struct syscall_data data = {};
	struct tracing *tc;
	char comm[25];
	__u32 key_map_config = 0;
	__u32 key_map_trace = 0;

	tc = bpf_map_lookup_elem(&tracing_status, &key_map_trace);
	if (!tc) {
		bpf_printk("error getting tracing status\n");
		return 1;
	}
	if (tc->status != 1) {
		//bpf_printk("tracing is not active, status=%d", tc->status);
		return 1;
	}

	bpf_get_current_comm(&comm, sizeof(comm));

	// lookup command passed as argument from Go application
	char *input_command = bpf_map_lookup_elem(&config_map, &key_map_config);
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
	bpf_printk("sending syscall ID: %d", id);
	return 0;
}

/*
	Used to unlock some useful helpers
	More information here:
	https://github.com/nyrahul/ebpf-guide/blob/master/docs/gpl_license_ebpf.rst
*/
char __license[] SEC("license") = "GPL";