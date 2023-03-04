#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <argp.h>
#include "cpu.h"

extern void display_loop(void);

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

int main(int argc, char **argv)
{
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!is_hybrid_cpu()) {
        fprintf(stderr, "This is not an Intel hybrid CPU, it's meaningless to "
                        "run this tool\n");
        return EXIT_FAILURE;
    }

    display_loop();

    return EXIT_SUCCESS;
}
