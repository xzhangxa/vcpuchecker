#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include "common.h"
#include "kvm_exit.h"
#include "hfi.h"

volatile bool exiting = false;

static void update_core_info(struct core_info *info)
{
    // TODO
}

static void update_vcpu_info(struct vcpu_info *info)
{
    // TODO
}

static void kvm_exit_func(struct kvm_exit_info *info)
{
    printf(
        "process=%s(%u-%u) vcpu_id=%d cpu=%u->%u exit_reason=%s duration=%luns\n",
        info->comm, info->tgid, info->pid, info->vcpu_id, info->orig_cpu, info->cpu,
        vmx_exit_str(info->exit_reason), info->time_ns);
    // TODO update_vcpu_info
}

static void kvm_exit_loop()
{
    int err;

    err = bpf_init(kvm_exit_func);
    if (err)
        goto cleanup;

    while (!exiting)
        err = bpf_rb_poll(100);

cleanup:
    bpf_exit();
}

static void hfi_cb(struct perf_cap *perf_cap)
{
    printf("cpu id %d, \tperf/eff [%d/%d]\n", perf_cap->cpu, perf_cap->perf,
           perf_cap->eff);
    // TODO update_core_info
}

static void hfi_event_loop()
{
    int err;

    while (!exiting && !err)
        err = hfi_recvmsg();
}

void display_loop(void)
{
    int err;
    bool hfi_inited = false;

    // TODO get all CPU cores and save core_info map
    // TODO get KVM guest domains and vcpu info and save to vcpu_info

    err = hfi_init(hfi_cb);
    if (err) {
        fprintf(stderr, "Warning: cannot get HFI info from kernel, probably "
                        "the kernel is older than 5.18 or config "
                        "CONFIG_INTEL_HFI_THERMAL is not enabled;\n"
                        "Warning: no HFI per core info available\n");
        hfi_inited = false;
    } else {
        hfi_inited = true;
    }

    std::thread bpf_thread{kvm_exit_loop};
    std::thread hfi_thread;
    if (hfi_inited)
        hfi_thread = std::thread{hfi_event_loop};

    if (bpf_thread.joinable())
        bpf_thread.join();
    if (hfi_thread.joinable())
        hfi_thread.join();
}
