#include <argp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "kvm_exit.h"

static struct env {
    long min_duration_ms;
} env;

const char *argp_program_version = "vcpuchecker 0.0";
const char argp_program_doc[] =
    "KVM kvm_exit reasons.\n"
    "\n"
    "This tool traces kvm guest vcpu schedule and associated \n"
    "information (filename, process duration, PID, etc).\n"
    "\n"
    "USAGE: ./vcpuchecker [-d <min-duration-ms>]\n";

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

static void kvm_exit_func(struct kvm_exit_info *info)
{
    printf("process=%s(%u) vcpu_id=%d cpu=%u->%u exit_reason=%s duration=%luns\n",
           info->comm, info->pid, info->vcpu_id, info->orig_cpu, info->cpu,
           vmx_exit_str(info->exit_reason), info->time_ns);
}

int main(int argc, char **argv)
{
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bpf_init(kvm_exit_func);
    if (err)
        goto cleanup;

    /* Process events */
    while (!exiting)
        err = bpf_rb_poll(100);

cleanup:
    bpf_exit();

    return err < 0 ? -err : 0;
}
