#include <stdlib.h>
#include <stdio.h>
#include <sys/resource.h>
#include <asm/vmx.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "kvm_exit.h"
#include "kvm_exit.skel.h"
#include "vc_event.h"

const char *vmx_exit_str(__u32 exit_reason)
{
    struct reason_strs {
        __u32 exit_reason;
        const char *reason_str;
    };
    struct reason_strs strs[] = {VMX_EXIT_REASONS};

    for (int i = 0; i < sizeof(strs) / sizeof(struct reason_strs); i++) {
        if (strs[i].exit_reason == exit_reason)
            return strs[i].reason_str;
    }

    return "unkown exit reason";
}

static kvm_exit_callback _callback = NULL;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct kvm_exit_info *e = data;

    if (_callback)
        _callback(e);

    return 0;
}

static struct ring_buffer *rb = NULL;
static struct kvm_exit_bpf *skel;

int bpf_init(kvm_exit_callback callback)
{
    int err;

    /* Load and verify BPF application */
    skel = kvm_exit_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    /* Load & verify BPF programs */
    err = kvm_exit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = kvm_exit_bpf__attach(skel);
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

    _callback = callback;

    return 0;

cleanup:
    kvm_exit_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}

void bpf_exit()
{
    _callback = NULL;
    ring_buffer__free(rb);
    kvm_exit_bpf__destroy(skel);
}

int bpf_rb_poll(int timeout_ms)
{
    int err;

    err = ring_buffer__poll(rb, timeout_ms /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR)
        err = 0;
    if (err < 0)
        printf("Error polling perf buffer: %d\n", err);

    return err;
}
