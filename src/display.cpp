#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <thread>
#include <chrono>
#include <mutex>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <libvirt/libvirt.h>
#include "cpu.h"
#include "kvm_exit.h"
#include "hfi.h"

using namespace std::chrono_literals;
using namespace std::chrono;
namespace fs = std::filesystem;

using time_ns = std::chrono::time_point<std::chrono::system_clock>;

static volatile bool exiting = false;

static std::mutex _g_mutex;
static std::map<int, struct core_info> _core_map;
static std::map<pid_t, struct vcpu_info> _vcpu_map;

struct vcpu_info {
    pid_t qemu_pid;
    unsigned int domain_id;
    std::string domain_name;
    size_t vcpu_num;
    std::vector<int> curr_cpu;

    std::vector<time_ns> start_time;
    std::vector<time_ns> last_time;
    std::vector<double> percent_on_perf_core;
};

int init_core_info(void)
{
    for (int i = 0; i < total_cpu_num(); i++) {
        _core_map[i].id = i;
        if (per_core_data(&_core_map[i]))
            return -1;

        /*
         * Init the perf/effi values based on the most common values if no CPU
         * load, in case:
         * 1. Kernel is old or INTEL_HFI_THERMAL is not enabled
         * 2. Some models report HFI data rarely, so after booting up the user
         *    space will not get a notification for a long time.
         * So these values are given manually, if HFI notification is properly
         * set and the CPU models do report often, it could be changed anytime
         * a HFI data notification is sent to user space.
         */
        if (_core_map[i].type == INTEL_CORE) {
            _core_map[i].perf = 256;
            _core_map[i].effi = 368;
        } else if (_core_map[i].type == INTEL_ATOM) {
            _core_map[i].perf = 152;
            _core_map[i].effi = 400;
        }
    }

    return 0;
}

static void update_core_info(int id, int perf, int effi)
{
    std::lock_guard<std::mutex> guard(_g_mutex);
    if (_core_map.find(id) != _core_map.end()) {
        _core_map[id].perf = perf;
        _core_map[id].effi = effi;
    }
}

static pid_t get_qemu_pid_by_domain(virDomainPtr d)
{
    const char *d_name;
    pid_t qemu_pid;

    d_name = virDomainGetName(d);
    std::string f_name =
        "/var/run/libvirt/qemu/" + std::string{d_name} + ".pid";
    std::ifstream fs(f_name);
    std::stringstream buffer;
    buffer << fs.rdbuf();
    try {
        qemu_pid = stoul(buffer.str());
    } catch (std::exception &e) {
        return 0;
    }

    return qemu_pid;
}

static virDomainPtr get_domain_by_qemu_pid(pid_t qemu_pid)
{
    pid_t tmp;
    virDomainPtr d = NULL;

    std::string path = "/var/run/libvirt/qemu/";
    for (const auto &entry : fs::directory_iterator(path)) {
        if (strcmp(entry.path().extension().c_str(), ".pid"))
            continue;
        tmp = 0;
        std::ifstream fs(entry.path());
        std::stringstream buffer;
        buffer << fs.rdbuf();
        try {
            tmp = stoul(buffer.str());
        } catch (std::exception &e) {
            continue;
        }
        if (tmp == qemu_pid) {
            virConnectPtr c = virConnectOpen(NULL);
            if (!c)
                return d;
            d = virDomainLookupByName(c, entry.path().stem().c_str());
            break;
        }
    }

    return d;
}

static void add_vcpu_info_by_domain(virDomainPtr d, pid_t qemu_pid)
{
    int ret;
    vcpu_info info;
    const char *d_name;
    size_t name_len;
    virDomainInfoPtr dinfo;
    virVcpuInfoPtr cpuinfo;

    dinfo = (virDomainInfoPtr)malloc(sizeof(virDomainInfo));
    if (!dinfo) {
        fprintf(stderr, "cannot allocate memory for domain info\n");
        return;
    }
    ret = virDomainGetInfo(d, dinfo);
    if (ret) {
        fprintf(stderr, "cannot get domain info\n");
        return;
    }
    info.domain_id = virDomainGetID(d);
    d_name = virDomainGetName(d);
    info.domain_name = d_name;
    info.vcpu_num = dinfo->nrVirtCpu;
    info.curr_cpu.resize(info.vcpu_num);

    cpuinfo = (virVcpuInfoPtr)malloc(sizeof(virVcpuInfo) * dinfo->nrVirtCpu);
    if (!cpuinfo) {
        fprintf(stderr, "cannot allocate memory for domain vcpu info\n");
        return;
    }

    // ret may be different to virDomainInfo.nrVirtCpu
    ret = virDomainGetVcpus(d, cpuinfo, dinfo->nrVirtCpu, NULL, 0);
    for (size_t i = 0; i < ret; i++)
        info.curr_cpu[i] = cpuinfo[i].cpu;

    // time
    time_ns curr = system_clock::now();
    info.start_time.resize(info.vcpu_num, curr);
    info.last_time.resize(info.vcpu_num, curr);
    info.percent_on_perf_core.resize(info.vcpu_num);
    for (size_t i = 0; i < info.vcpu_num; i++) {
        auto core = _core_map.find(info.curr_cpu[i]);
        if (core == _core_map.end()) {
            fprintf(stderr, "cannot find core info, likely programming error");
            return;
        }
        if (core->second.type == INTEL_CORE)
            info.percent_on_perf_core[i] = 1.0;
    }

    free(cpuinfo);
    free(dinfo);

    if (!qemu_pid) {
        qemu_pid = get_qemu_pid_by_domain(d);
        if (!qemu_pid) {
            fprintf(stderr, "cannot find qemu pid of domain\n");
            return;
        }
    }

    _vcpu_map[qemu_pid] = info;
}

static void add_vcpu_info_by_pid(pid_t qemu_pid)
{
    virDomainPtr d;

    d = get_domain_by_qemu_pid(qemu_pid);
    if (d) {
        add_vcpu_info_by_domain(d, qemu_pid);
        virDomainFree(d);
    }
}

static int init_vcpu_info(void)
{
    int ret;
    virConnectPtr c;
    virDomainPtr *d;
    unsigned int flags =
        VIR_CONNECT_LIST_DOMAINS_RUNNING | VIR_CONNECT_LIST_DOMAINS_PERSISTENT;

    c = virConnectOpen(NULL);
    if (!c) {
        fprintf(stderr, "cannot connect to libvirtd");
        return -1;
    }
    ret = virConnectListAllDomains(c, &d, flags);
    for (int i = 0; i < ret; i++) {
        add_vcpu_info_by_domain(d[i], 0);
        virDomainFree(d[i]);
    }
    free(d);

    return 0;
}

static void update_percentage(struct vcpu_info &info, unsigned int vcpu_id)
{
    auto curr = system_clock::now();
    auto start = info.start_time[vcpu_id];
    auto last = info.last_time[vcpu_id];
    auto old_percent = info.percent_on_perf_core[vcpu_id];
    double new_percent;

    info.last_time[vcpu_id] = curr;

    auto core = _core_map.find(info.curr_cpu[vcpu_id]);
    if (core == _core_map.end()) {
        fprintf(stderr, "cannot find core info, likely programming error");
        return;
    }
    int on_P = (core->second.type == INTEL_CORE) ? 1 : 0;

    auto total_ns = duration_cast<nanoseconds>(curr - start).count();
    auto last_ns = duration_cast<nanoseconds>(last - start).count();
    auto passing_ns = duration_cast<nanoseconds>(curr - last).count();

    new_percent = (last_ns * old_percent + passing_ns * on_P) / total_ns;

    info.percent_on_perf_core[vcpu_id] = new_percent;
}

static void update_vcpu_info(pid_t qemu_id, unsigned int vcpu_id,
                             unsigned int orig_cpu, unsigned int cpu,
                             uint64_t time_ns)
{
    std::lock_guard<std::mutex> guard(_g_mutex);

    if (_vcpu_map.find(qemu_id) == _vcpu_map.end())
        add_vcpu_info_by_pid(qemu_id);

    auto &domain = _vcpu_map[qemu_id];

    // update vcpu P-core percent
    update_percentage(domain, vcpu_id);

    domain.curr_cpu[vcpu_id] = cpu;

}

static void kvm_exit_func(struct kvm_exit_info *info)
{
    /*
    printf("process=%s(%u-%u) vcpu_id=%d cpu=%u->%u exit_reason=%s "
           "duration=%luns\n",
           info->comm, info->tgid, info->pid, info->vcpu_id, info->orig_cpu,
           info->cpu, vmx_exit_str(info->exit_reason), info->time_ns);
    */
    update_vcpu_info(info->tgid, info->vcpu_id, info->orig_cpu, info->cpu,
                     info->time_ns);
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
    update_core_info(perf_cap->cpu, perf_cap->perf, perf_cap->eff);
}

static void hfi_event_loop()
{
    int err = 0;

    while (!exiting && !err) {
        err = hfi_recvmsg();
        std::this_thread::sleep_for(1s);
    }
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

    err = init_vcpu_info();
    if (err)
        return;

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
        std::unique_lock<std::mutex> lock(_g_mutex);
        for (auto it = _vcpu_map.begin(); it != _vcpu_map.end(); it++) {
            printf("KVM guest domain %s (id %u) (qemu pid %u)\n",
                   it->second.domain_name.c_str(), it->second.domain_id,
                   it->first);
            for (int i = 0; i < it->second.vcpu_num; i++) {
                update_percentage(it->second, i);
                printf("\tvcpu %u \t-> Core %d \t%f%% on P-core\n", i,
                       it->second.curr_cpu[i],
                       it->second.percent_on_perf_core[i] * 100);
            }
        }
        for (auto it = _core_map.cbegin(); it != _core_map.cend(); it++) {
            printf("Core %d (%d, %s) - perf %u effi %u\n", it->first,
                   it->second.core_id,
                   (it->second.type == INTEL_CORE) ? "P-core" : "E-core",
                   it->second.perf, it->second.effi);
        }
        lock.unlock();
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
