#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <argp.h>
#include "common.h"
#include "kvm_exit.h"
#include "hfi.h"

static struct env {
    long min_duration_ms;
} env;

const char *argp_program_version = "vcpuchecker 0.0";
const char argp_program_doc[] =
    "Check KVM guest vcpu scheduling on physical cores.\n"
    "\n"
    "This tool traces kvm guest vcpu schedule and associated \n"
    "information (filename, process duration, PID, etc).\n"
    "\n"
    "USAGE: sudo ./vcpuchecker\n";

static const struct argp_option opts[] = {
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static void kvm_exit_func(struct kvm_exit_info *info)
{
    printf(
        "process=%s(%u-%u) vcpu_id=%d cpu=%u->%u exit_reason=%s duration=%luns\n",
        info->comm, info->tgid, info->pid, info->vcpu_id, info->orig_cpu, info->cpu,
        vmx_exit_str(info->exit_reason), info->time_ns);
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
}

static void hfi_event_loop()
{
    int err;

    while (!exiting && !err)
        err = hfi_recvmsg();
}

int main(int argc, char **argv)
{
    int err;
    bool hfi_inited = false;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!is_hfi_support()) {
        fprintf(stderr, "Intel Hardware Feedback Interface is not found on the "
                        "CPU, it's meaningless to run this tool on non-12/13 "
                        "gen Intel Core CPUs\n");
        return EXIT_FAILURE;
    }

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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    std::thread bpf_thread{kvm_exit_loop};
    std::thread hfi_thread;
    if (hfi_inited)
        hfi_thread = std::thread{hfi_event_loop};

    if (bpf_thread.joinable())
        bpf_thread.join();
    if (hfi_thread.joinable())
        hfi_thread.join();

    return EXIT_SUCCESS;
}
