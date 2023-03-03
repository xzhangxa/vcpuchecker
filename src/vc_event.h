#ifndef _VC_EVENT_H_
#define _VC_EVENT_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct kvm_exit_info {
    uint32_t pid;
    uint32_t tgid;
    char comm[TASK_COMM_LEN];
    uint32_t vcpu_id;
    uint32_t cpu;
    uint32_t orig_cpu;
    uint32_t exit_reason;
    uint64_t time_ns;
};

#endif /* _VC_EVENT_H_ */
