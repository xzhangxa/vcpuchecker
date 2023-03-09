#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include "cpu.h"

#define PROCSTATFILE "/proc/stat"
#define PROCLINELEN 4096

static bool _stat_uninit = true;

int init_core_info(struct core_info **infos, int *core_num)
{
    struct core_info *info;
    int num = total_cpu_num();

    *infos = (struct core_info *)calloc(num, sizeof(struct core_info));
    if (!*infos)
        return -1;

    memset(*infos, 0, num * sizeof(struct core_info));

    for (int i = 0; i < num; i++) {
        info = &(*infos)[i];
        info->id = i;
        if (per_core_data(info)) {
            free(*infos);
            return -1;
        }

        /*
         * Init the perf/effi values based on the most common values if no CPU
         * load, in case:
         * 1. Kernel is old or INTEL_HFI_THERMAL is not enabled
         * 2. Some models report HFI data rarely, so after booting up the user
         *    space will not get a notification for a long time.
         * So these values are given manually, if HFI notification is properly
         * set and the CPU models do report often, it could be changed anytime
         * a HFI data notification is sent to user space.
         */
        if (info->type == INTEL_CORE) {
            info->perf = 256;
            info->effi = 368;
        } else if (info->type == INTEL_ATOM) {
            info->perf = 152;
            info->effi = 400;
        }
    }

    update_cpu_utilization(*infos, num);

    *core_num = num;

    return 0;
}

void clear_core_info(struct core_info **infos) { free(*infos); }

static inline unsigned long long saturating_sub(unsigned long long a,
                                                unsigned long long b)
{
    return (a > b) ? a - b : 0;
}

void update_cpu_utilization(struct core_info *infos, int core_num)
{
    bool total_cpu_line = true;

    FILE *fp = fopen(PROCSTATFILE, "r");
    if (!fp)
        return;

    while (1) {
        char buf[PROCLINELEN + 1];
        unsigned int cpuid;
        unsigned long long user = 0, nice = 0, system = 0, idle = 0, iowait = 0,
                           irq = 0, softirq = 0, steal = 0, guest = 0,
                           guestnice = 0;
        const char *err = fgets(buf, PROCLINELEN, fp);
        if (!err)
            break;

        if (strncmp(buf, "cpu", strlen("cpu")))
            break;

        if (total_cpu_line) {
            total_cpu_line = false;
            continue;
        }

        sscanf(buf,
               "cpu%4u %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu "
               "%16llu %16llu",
               &cpuid, &user, &nice, &system, &idle, &iowait, &irq, &softirq,
               &steal, &guest, &guestnice);

        unsigned long long total = user + nice + system + idle + iowait + irq +
                                   softirq + steal + guest + guestnice;

        if (_stat_uninit) {
            infos[cpuid].precent = 0.0;
        } else {
            unsigned long long total_time =
                saturating_sub(total, infos[cpuid]._total);
            double total_d = (double)(total_time == 0 ? 1 : total_time);
            double user_time =
                saturating_sub(user, infos[cpuid]._user) / total_d;
            double nice_time =
                saturating_sub(nice, infos[cpuid]._nice) / total_d;
            double system_time =
                saturating_sub(system, infos[cpuid]._system) / total_d;
            double irq_time = saturating_sub(irq, infos[cpuid]._irq) / total_d;
            double softirq_time =
                saturating_sub(softirq, infos[cpuid]._softirq) / total_d;
            double steal_time =
                saturating_sub(steal, infos[cpuid]._steal) / total_d;
            double guest_time =
                saturating_sub(guest, infos[cpuid]._guest) / total_d;
            double guestnice_time =
                saturating_sub(guestnice, infos[cpuid]._guestnice) / total_d;

            infos[cpuid].precent = user_time + nice_time + system_time +
                                   irq_time + softirq_time + steal_time +
                                   guest_time + guestnice_time;
        }

        infos[cpuid]._user = user;
        infos[cpuid]._nice = nice;
        infos[cpuid]._system = system;
        infos[cpuid]._idle = idle;
        infos[cpuid]._iowait = iowait;
        infos[cpuid]._irq = irq;
        infos[cpuid]._softirq = softirq;
        infos[cpuid]._steal = steal;
        infos[cpuid]._guest = guest;
        infos[cpuid]._guestnice = guestnice;
        infos[cpuid]._total = total;
    }

    _stat_uninit = false;

    fclose(fp);
}

struct _result {
    int cpu;
    int core_id;
    int type;
};

static void *_per_core_func(void *arg)
{
    cpu_set_t cpuset;
    struct _result *result = (struct _result *)arg;

    CPU_ZERO(&cpuset);
    CPU_SET(result->cpu, &cpuset);
    pthread_t self = pthread_self();
    pthread_setaffinity_np(self, sizeof(cpu_set_t), &cpuset);

    result->type = CPUID_MASK(0x1a, eax, 0xFF000000, 24);

    int level = CPUID_MASK(0, eax, 0xFFFFFFFF, 0);
    if (level >= 0x1F)
        level = 0x1F;
    else if (level >= 0xB)
        level = 0xB;
    int initial_apicid = CPUID_MASK(level, edx, 0xFFFFFFFF, 0);
    int shift = CPUID_MASK(level, eax, 0x1F, 0);
    result->core_id = initial_apicid >> shift;

    return NULL;
}

inline int per_core_data(struct core_info *info)
{
    pthread_t t;
    int ret;
    struct _result result;

    result.cpu = info->id;
    ret = pthread_create(&t, NULL, _per_core_func, &result);
    if (ret)
        return -1;
    ret = pthread_join(t, NULL);
    if (ret)
        return -1;

    info->type = (enum core_type)result.type;
    info->core_id = result.core_id;

    return 0;
}
