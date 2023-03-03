#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <argp.h>
#include "common.h"

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

static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv)
{
    int err;

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

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    display_loop();

    return EXIT_SUCCESS;
}
