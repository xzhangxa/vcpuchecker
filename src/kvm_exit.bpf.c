#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vc_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct vc_exit_value {
    u32 cpu;
    u32 exit_reason;
    u64 time_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct vc_exit_value);
} kvm_exit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* dump from /sys/kernel/debug/tracing/events/kvm/kvm_exit/format */
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
int check_kvm_exit(struct kvm_exit_args *args)
{
    int i;
    u32 vcpu_id;
    u32 exit_reason;
    u32 cpu;
    struct vc_exit_value value;

    vcpu_id = args->vcpu_id;
    exit_reason = args->exit_reason;
    cpu = bpf_get_smp_processor_id();
    // update BPF map
    value.cpu = cpu;
    value.exit_reason = exit_reason;
    value.time_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&kvm_exit_map, &vcpu_id, &value, BPF_ANY);

    return 0;
}

/* dump from /sys/kernel/debug/tracing/events/kvm/kvm_entry/format */
struct kvm_entry_args {
    u64 padding;
    unsigned int vcpu_id;
    unsigned long rip;
};
SEC("tp/kvm/kvm_entry")
int check_kvm_entry(struct kvm_entry_args *args)
{
    int i;
    struct kvm_exit_info *e;
    u32 orig_cpu, cpu;
    u32 vcpu_id;
    u32 exit_reason;
    u64 time_ns;
    struct vc_exit_value *value;

    vcpu_id = args->vcpu_id;
    cpu = bpf_get_smp_processor_id();

    value = bpf_map_lookup_elem(&kvm_exit_map, &vcpu_id);
    if (!value)
        return 0;

    orig_cpu = value->cpu;
    exit_reason = value->exit_reason;
    time_ns = bpf_ktime_get_ns() - value->time_ns;
    bpf_map_delete_elem(&kvm_exit_map, &vcpu_id);

    if (cpu == orig_cpu)
        return 0;

    // send ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->vcpu_id = vcpu_id;
    e->cpu = cpu;
    e->orig_cpu = orig_cpu;
    e->exit_reason = exit_reason;
    e->time_ns = time_ns;
    bpf_get_current_comm(e->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

#if 0
#ifdef CONFIG_X86_64
#define MAX_NR_USER_RETURN_MSRS 7
#else
#define MAX_NR_USER_RETURN_MSRS 4
#endif
#define MAX_NR_LOADSTORE_MSRS 8
struct vmx_uret_msr {
	bool load_into_hardware;
	u64 data;
	u64 mask;
};
struct vmcs_hdr {
	u32 revision_id:31;
	u32 shadow_vmcs:1;
};
struct vmcs {
	struct vmcs_hdr hdr;
	u32 abort;
	char data[];
};
struct vmcs_host_state {
	unsigned long cr3;	/* May not match real cr3 */
	unsigned long cr4;	/* May not match real cr4 */
	unsigned long gs_base;
	unsigned long fs_base;
	unsigned long rsp;
	u16           fs_sel, gs_sel, ldt_sel;
#ifdef CONFIG_X86_64
	u16           ds_sel, es_sel;
#endif
};
struct vmcs_controls_shadow {
	u32 vm_entry;
	u32 vm_exit;
	u32 pin;
	u32 exec;
	u32 secondary_exec;
	u64 tertiary_exec;
};
struct loaded_vmcs {
	struct vmcs *vmcs;
	struct vmcs *shadow_vmcs;
	int cpu;
	bool launched;
	bool nmi_known_unmasked;
	bool hv_timer_soft_disabled;
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	unsigned long *msr_bitmap;
	struct list_head loaded_vmcss_on_cpu_link;
	struct vmcs_host_state host_state;
	struct vmcs_controls_shadow controls_shadow;
};
struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 value;
} __attribute__((aligned(16)));
struct vmx_msrs {
	unsigned int		nr;
	struct vmx_msr_entry	val[MAX_NR_LOADSTORE_MSRS];
};
union vmx_exit_reason {
	struct {
		u32	basic			: 16;
		u32	reserved16		: 1;
		u32	reserved17		: 1;
		u32	reserved18		: 1;
		u32	reserved19		: 1;
		u32	reserved20		: 1;
		u32	reserved21		: 1;
		u32	reserved22		: 1;
		u32	reserved23		: 1;
		u32	reserved24		: 1;
		u32	reserved25		: 1;
		u32	bus_lock_detected	: 1;
		u32	enclave_mode		: 1;
		u32	smi_pending_mtf		: 1;
		u32	smi_from_vmx_root	: 1;
		u32	reserved30		: 1;
		u32	failed_vmentry		: 1;
	};
	u32 full;
};
struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	u8                    fail;
	u8		      x2apic_msr_bitmap_mode;
	bool		      guest_state_loaded;
	unsigned long         exit_qualification;
	u32                   exit_intr_info;
	u32                   idt_vectoring_info;
	ulong                 rflags;
	struct vmx_uret_msr   guest_uret_msrs[MAX_NR_USER_RETURN_MSRS];
	bool                  guest_uret_msrs_loaded;
#ifdef CONFIG_X86_64
	u64		      msr_host_kernel_gs_base;
	u64		      msr_guest_kernel_gs_base;
#endif
	u64		      spec_ctrl;
	u32		      msr_ia32_umwait_control;
	struct loaded_vmcs    vmcs01;
	struct loaded_vmcs   *loaded_vmcs;

	struct msr_autoload {
		struct vmx_msrs guest;
		struct vmx_msrs host;
	} msr_autoload;

	struct msr_autostore {
		struct vmx_msrs guest;
	} msr_autostore;

	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_segment segs[8];
	} rmode;
	struct {
		u32 bitmask; /* 4 bits per segment (1 bit per field) */
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} seg[8];
	} segment_cache;
	int vpid;
	bool emulation_required;

	union vmx_exit_reason exit_reason;
};

SEC("raw_tracepoint/kvm_exit")
int check_raw_kvm_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct kvm_exit_info *e;
    struct kvm_vcpu *vcpu = (struct kvm_vcpu *)ctx->args[0];
    struct vcpu_vmx *vmx = container_of(vcpu, struct vcpu_vmx, vcpu);
    u32 isa = (u32)ctx->args[1];

    // send ringbuf
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->vcpu_id = BPF_CORE_READ(vcpu, vcpu_id);
    e->cpu = BPF_CORE_READ(vcpu, cpu);
    e->exit_reason = BPF_CORE_READ(vmx, exit_reason.full);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
#endif
