#ifndef _CPU_H_
#define _CPU_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <cpuid.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sched.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _BIT(x) (1 << (x))

enum core_type {
    INTEL_CORE = 0x40,
    INTEL_ATOM = 0x20,
    INTEL_GENERIC = 0x0
};

struct core_info {
    int id;
    uint8_t perf;
    uint8_t effi;
    int ht_pair;
    enum core_type type;
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

struct _result {
    int cpu;
    int result;
};

inline static void *threadFunc(void *arg)
{
    cpu_set_t cpuset;
    struct _result *result = (struct _result*)arg;
    CPU_ZERO(&cpuset);
    CPU_SET(result->cpu, &cpuset);

    pthread_t self = pthread_self();
    pthread_setaffinity_np(self, sizeof(cpu_set_t), &cpuset);
    result->result = CPUID_MASK(0x1a, eax, 0xFF000000, 24);
    return NULL;
}

inline static enum core_type hybrid_core_type(int id)
{
    pthread_t t;
    int ret;
    struct _result result;

    result.cpu = id;
    ret = pthread_create(&t, NULL, threadFunc, &result);
    if (ret)
        return INTEL_GENERIC;
    ret = pthread_join(t, NULL);
    if (ret)
        return INTEL_GENERIC;

    return (enum core_type)result.result;
}

inline static int total_cpu_num(void) { return sysconf(_SC_NPROCESSORS_ONLN); }

#ifdef __cplusplus
}
#endif

#endif // _CPU_H_
