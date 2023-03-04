#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <map>
#include "cpu.h"
#include "kvm_exit.h"
#include "hfi.h"

using namespace std::chrono_literals;

static volatile bool exiting = false;

static std::mutex _map_mutex;
static std::map<int, struct core_info> _core_map;

struct vcpu_info {
    unsigned int vcpu_id;
    unsigned int curr_cpu;
    unsigned int domain_id;
    double percent_on_perf_core;
};

int init_core_info(void)
{
    for (int i = 0; i < total_cpu_num(); i++) {
        _core_map[i].id = i;
        _core_map[i].type = hybrid_core_type(i);
    }
    return 0;
}

static void update_core_info(int id, uint8_t perf, uint8_t effi)
{
    std::lock_guard<std::mutex> guard(_map_mutex);
    if (_core_map.find(id) != _core_map.end()) {
        _core_map[id].perf = perf;
        _core_map[id].effi = effi;
    }
}

static void update_vcpu_info(struct vcpu_info &info)
{
    // TODO
}

static void kvm_exit_func(struct kvm_exit_info *info)
{
    printf("process=%s(%u-%u) vcpu_id=%d cpu=%u->%u exit_reason=%s "
           "duration=%luns\n",
           info->comm, info->tgid, info->pid, info->vcpu_id, info->orig_cpu,
           info->cpu, vmx_exit_str(info->exit_reason), info->time_ns);
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
    update_core_info(perf_cap->cpu, (uint8_t)perf_cap->perf,
                     (uint8_t)perf_cap->eff);
}

static void hfi_event_loop()
{
    int err;

    while (!exiting && !err)
        err = hfi_recvmsg();
}

static void sig_handler(int sig) { exiting = true; }

#ifdef __cplusplus
extern "C" {
#endif

void display_loop(void)
{
    int err;
    bool hfi_inited = false;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = init_core_info();
    if (err)
        return;
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

    while (!exiting) {
        printf("==========================================================\n");
        std::lock_guard<std::mutex> guard(_map_mutex);
        for (auto it = _core_map.begin(); it != _core_map.end(); it++) {
            printf("Core %d (%s)- perf %u effi %u\n", it->first,
                   (it->second.type == INTEL_CORE) ? "P-core" : "E-core",
                   it->second.perf, it->second.effi);
        }
        std::this_thread::sleep_for(1000ms);
    }

    if (bpf_thread.joinable())
        bpf_thread.join();
    if (hfi_thread.joinable())
        hfi_thread.join();
}

#ifdef __cplusplus
}
#endif
