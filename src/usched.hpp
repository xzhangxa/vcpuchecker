#ifndef _USCHED_HPP_
#define _USCHED_HPP_
#include <queue>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    CPU_NAME = 0,
    CPU_USER = 1,
    CPU_NICE = 2,
    CPU_SYSTEM = 3,
    CPU_IDLE = 4,
    CPU_IOWAIT = 5,
    CPU_IRRQ = 6,
    CPU_SOFTIRQ = 7,
    CPU_STEAL = 8,
    CPU_GUEST = 9,
    CPU_GUEST_NICE = 10
};

enum SCHEDPOLICY { OTHER = 0, FIFO = 1, RR = 2 };

struct pid_usage_info {
    double percent;

    unsigned long long utime;
    unsigned long long stime;

    pid_usage_info() {}
    pid_usage_info(double percent, unsigned long long utime,
                   unsigned long long stime)
    {
        this->percent = percent;
        this->utime = utime;
        this->stime = stime;
    }
};
struct pid_info {
    pid_t _thread_id;
    pid_t ppid;
    int last_cpu;
    std::queue<int> cpuoff;
    bool sched;
    struct pid_usage_info _pid_usage_info;

    pid_info() {}
    pid_info(pid_t _thread_id, pid_t ppid, int last_cpu,
             struct pid_usage_info pui)
    {
        this->ppid = ppid;
        this->_thread_id = _thread_id;
        this->last_cpu = last_cpu;
        this->sched = false;
        this->_pid_usage_info = pui;
    }

    ~pid_info() {}
};
enum MASK_DIR { CPUON, CPUOFF };
enum TID_STAT_ITEM {
    STATE = 0,
    PPID,
    PGRP,
    SESSION,
    TTY_NR,
    TPGID,
    FLAGS,
    MINFLT,
    CMINFLT,
    MAJFLT,
    CMAJFLT,
    UTIME,
    STIME,
    CUTIME,
    CSTIME,
    PRIORITY,
    NICE,
    NUM_THREADS,
    ITREALVALUE,
    STARTTIME,
    VSIZE,
    RSS,
    RSSLIM,
    STARTCODE,
    ENDCODE,
    STARTSTACK,
    KSTKESP,
    KSTKEIP,
    SIGNAL,
    BLOCKED,
    SIGIGNORE,
    SIGCATCH,
    WCHAN,
    NSWAP,
    CNSWAP,
    EXIT_SIGNAL,
    PROCESSOR,
    RT_PRIORITY,
    POLICY,
    DELAYACCT_BLKIO_TICKS,
    GUEST_TIME,
    CGUST_TIME,
    START_DATA,
    END_DATA,
    START_BRK,
    ARG_START,
    ARG_END,
    ENV_START,
    ENV_END,
    EXIT_CODE
};

extern bool upsert_to_monitor_pool(pid_t qemu_id, pid_t tid,
                                   struct pid_info *_pid_info,
                                   struct core_info *_core_map);
extern void usched_entry(struct core_info *_core_info);
extern pid_t usched_check(struct core_info *_core_info,
                          struct pid_info *_pid_info);
extern bool usched_commit_change(pid_t _thread_id);
extern bool usched_revert_change(pid_t _thread_id);
extern bool set_affinity_byid(pid_t _thread_id, int num_cpu, enum MASK_DIR md);
extern void set_usched_threshold(unsigned int num);
extern void remove_from_monitor_pool(pid_t qemu_id, pid_t tid);

#ifdef __cplusplus
}
#endif

#endif
