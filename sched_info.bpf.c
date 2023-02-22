#include "vmlinux.h"
// #include <asm/vmx.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "sched_info.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u64);
} kvm_exit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct kvm_exit_args {
    u64 padding;
    unsigned int exit_reason;
    unsigned long guest_rip;
    u32 isa;
    u64 info1;
    u64 info2;
    u32 intr_info;
    u32 error_code;
    unsigned int vcpu_id;
};
SEC("tp/kvm/kvm_exit")
int check_kvm_exit(struct kvm_exit_args *args) {
    int i;
    struct event *e;
    u64 *orig;
    u64 times;

    // update BPF map
    for (i = 0; i < 6; i++) {
        orig = bpf_map_lookup_elem(&kvm_exit_map, &e->pid);
        if (orig)
            times = *orig;
        else
            times = 0;
        times += 1;
        bpf_map_update_elem(&kvm_exit_map, &args->vcpu_id, &times, BPF_ANY);
    }

    // send ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->vcpu_id = args->vcpu_id;
    e->exit_reason = args->exit_reason;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// SEC("tp/kvm/kvm_entry")
// int handle_kvm_entry(struct kvm_vcpu *vcpu) { return 0; }
