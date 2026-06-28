#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct exec_event {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct exec_event *evt;
    evt = bpf_ringbuf_reserve(&exec_events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
