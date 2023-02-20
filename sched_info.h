#ifndef _SCHED_INFO_H_
#define _SCHED_INFO_H_

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 exit_reason;
    unsigned int vcpu_id;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif /* _SCHED_INFO_H_ */
