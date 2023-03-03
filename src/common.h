#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include <cpuid.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIT(x) (1 << (x))

extern volatile bool exiting;
extern void display_loop(void);

struct core_info {
    unsigned int id;
    uint8_t perf;
    uint8_t eff;
    unsigned int ht_pair;
    bool is_perf_core;
};

struct vcpu_info {
    unsigned int vcpu_id;
    unsigned int curr_cpu;
    unsigned int domain_id;
    double percent_on_perf_core;
};

inline static int cpuid_leaf6(int bit)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    __cpuid(6, eax, ebx, ecx, edx);
    if (eax & BIT(bit))
        return 1;

    return 0;
}

inline static int is_itmt_support(void) { return cpuid_leaf6(14); }
inline static int is_hfi_support(void) { return cpuid_leaf6(19); }
inline static int is_itd_support(void) { return cpuid_leaf6(23); }

#ifdef __cplusplus
}
#endif

#endif // _COMMON_H_
