#ifndef _CPU_H_
#define _CPU_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <cpuid.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sched.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _BIT(x) (1 << (x))

enum core_type { INTEL_CORE = 0x40, INTEL_ATOM = 0x20, INTEL_GENERIC = 0x0 };

struct core_info {
    int id;
    int perf;
    int effi;
    int core_id;
    enum core_type type;
    double precent;

    unsigned long long int _total;
    unsigned long long int _busy;
    unsigned long long int _user;
    unsigned long long int _nice;
    unsigned long long int _system;
    unsigned long long int _idle;
    unsigned long long int _iowait;
    unsigned long long int _irq;
    unsigned long long int _softirq;
    unsigned long long int _steal;
    unsigned long long int _guest;
    unsigned long long int _guestnice;
};

#define CPUID_BIT(LEAF, REG, BIT)                                              \
    ({                                                                         \
        unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;                       \
        __cpuid_count(LEAF, 0, eax, ebx, ecx, edx);                            \
        (REG & _BIT(BIT)) ? 1 : 0;                                             \
    })
#define CPUID_MASK(LEAF, REG, MASK, SHIFT)                                     \
    ({                                                                         \
        unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;                       \
        __cpuid_count(LEAF, 0, eax, ebx, ecx, edx);                            \
        (REG & MASK) >> SHIFT;                                                 \
    })

inline static int is_itmt_support(void) { return CPUID_BIT(0x6, eax, 14); }
inline static int is_hfi_support(void) { return CPUID_BIT(0x6, eax, 19); }
inline static int is_itd_support(void) { return CPUID_BIT(0x6, eax, 23); }
inline static int is_hybrid_cpu(void) { return CPUID_BIT(0x7, edx, 15); }

extern int init_core_info(struct core_info **infos, int *core_num);
extern void clear_core_info(struct core_info **infos);
extern int per_core_data(struct core_info *info);
extern void update_cpu_utilization(struct core_info *info, int cpu_num);

inline static int total_cpu_num(void) { return sysconf(_SC_NPROCESSORS_ONLN); }

#ifdef __cplusplus
}
#endif

#endif // _CPU_H_
