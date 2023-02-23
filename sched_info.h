#ifndef _SCHED_INFO_H_
#define _SCHED_INFO_H_

enum event_type {
    KVM_EXIT_VCPU_MAPPING_CHANGE,
    KVM_EXIT_ENTRY
};

struct event {
    enum event_type type;
    __u32 pid;
    __u32 vcpu_id;
    __u32 cpu;
    __u32 orig_cpu;
    __u32 exit_reason;
    bool raw_event;
};

#endif /* _SCHED_INFO_H_ */
