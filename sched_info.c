#include <argp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <asm/vmx.h>
#include <bpf/libbpf.h>
#include "sched_info.h"
#include "sched_info.skel.h"

static struct env {
    long min_duration_ms;
} env;

const char *argp_program_version = "sched_info 0.0";
const char argp_program_doc[] =
    "KVM kvm_exit reasons.\n"
    "\n"
    "This tool traces kvm guest vcpu schedule and associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./sched_info [-d <min-duration-ms>]\n";

static const struct argp_option opts[] = {
    {"duration", 'd', "DURATION-MS", 0,
     "Minimum process duration (ms) to report"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 'd':
        errno = 0;
        env.min_duration_ms = strtol(arg, NULL, 10);
        if (errno || env.min_duration_ms <= 0) {
            fprintf(stderr, "Invalid duration: %s\n", arg);
            argp_usage(state);
        }
        break;
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

static const char *vmx_exit_reason_str(__u32 exit_reason)
{
    struct reason_strs {
        __u32 exit_reason;
        const char *reason_str;
    };
    struct reason_strs strs[] = { VMX_EXIT_REASONS };

    for (int i = 0; i < sizeof(strs)/sizeof(struct reason_strs); i++) {
        if (strs[i].exit_reason == exit_reason)
            return strs[i].reason_str;
    }

    return "unkown exit reason";
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;

    if (e->type == KVM_EXIT_VCPU_MAPPING_CHANGE) {
        printf("event=KVM_EXIT_VCPU_MAPPING_CHANGE pid=%u vcpu_id=%d cpu=%d orig_cpu=%d exit_reason=%s\n",
               e->pid, e->vcpu_id, e->cpu, e->orig_cpu, vmx_exit_reason_str(e->exit_reason));
    } else if (e->type == KVM_EXIT_ENTRY) {
        //printf("event=KVM_EXIT_ENTRY pid=%u vcpu_id=%u cpu=%u orig_cpu=%u exit_reason=%s\n",
        //       e->pid, e->vcpu_id, e->cpu, e->orig_cpu, vmx_exit_reason_str(e->exit_reason));
    }

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct sched_info_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = sched_info_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = sched_info_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = sched_info_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    sched_info_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
