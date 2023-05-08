#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <argp.h>
#include <libvirt/libvirt.h>
#include "cpu.h"

#define SHM_SIZE (1 * 1024 * 1024)

#define QEMU_USER "libvirt-qemu"

static const char *_domain_name;

struct vcpu_info {
    int vcpu;
    int pcpu;
    int hwp_cap_hi_perf;
};

static int get_msr_hwp_cap(struct core_info *core)
{
    char msr_file[16];
    int8_t buf[8];

    sprintf(msr_file, "/dev/cpu/%d/msr", core->id);

    int fd = open(msr_file, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open %s: %s\n", msr_file, strerror(errno));
        return -1;
    }

    off_t off = lseek(fd, 0x771, SEEK_SET);
    if (off == -1 || off != 0x771) {
        fprintf(stderr, "Cannot read %s: %s\n", msr_file, strerror(errno));
        return -1;
    }

    ssize_t s = read(fd, buf, 8);
    if (s == -1 || s != 8) {
        fprintf(stderr, "Cannot read %s: %s\n", msr_file, strerror(errno));
        return -1;
    }

    core->hwp_cap_hi_perf = buf[0] & 0xFF;

    close(fd);

    return 0;
}

int set_shm(struct vcpu_info *cores, int count)
{
    char *p;
    int fd;

    struct passwd *pwd;
    struct group *grp;

    pwd = getpwnam(QEMU_USER);
    if (pwd == NULL)
        return -1;

    if (seteuid(pwd->pw_uid) == -1)
        return -1;

    fd = shm_open(_domain_name, O_RDWR | O_CREAT, 0640);
    if (fd == -1) {
        fprintf(stderr, "shm_open '%s' error: %s\n", _domain_name,
                strerror(errno));
        return -1;
    }

    if (ftruncate(fd, SHM_SIZE) == -1) {
        fprintf(stderr, "ftruncate '%s' error: %s\n", _domain_name,
                strerror(errno));
        return -1;
    }

    p = mmap(NULL, SHM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap error: %s\n", strerror(errno));
        return -1;
    }

    memset(p, 0, SHM_SIZE);

    for (int i = 0; i < count; i++)
        *((uint8_t *)p + i) = cores[i].hwp_cap_hi_perf;

    if (munmap(p, SHM_SIZE) == -1) {
        fprintf(stderr, "munmap error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int init_vcpu_info(struct vcpu_info **vcpus, int *count, const struct core_info *cores, int core_num)
{
    int rc;
    virDomainInfoPtr dinfo;
    unsigned char *cpumaps = NULL;
    int maplen;

    virConnectPtr c = virConnectOpen(NULL);
    if (!c)
        return -1;
    virDomainPtr d = virDomainLookupByName(c, _domain_name);
    if (!d)
        return -1;

    dinfo = (virDomainInfoPtr)malloc(sizeof(virDomainInfo));
    if (!dinfo) {
        virDomainFree(d);
        return -1;
    }

    rc = virDomainGetInfo(d, dinfo);
    if (rc) {
        virDomainFree(d);
        free(dinfo);
        return -1;
    }

    *count = dinfo->nrVirtCpu;

    *vcpus = (struct vcpu_info *)calloc(*count, sizeof(struct vcpu_info));
    if (!*vcpus)
        return -1;

    memset(*vcpus, 0, *count * sizeof(struct vcpu_info));
    maplen = VIR_CPU_MAPLEN(core_num);

    cpumaps = (unsigned char *)malloc(maplen * dinfo->nrVirtCpu);
    if (!cpumaps) {
        virDomainFree(d);
        free(dinfo);
        free(vcpus);
        return -1;
    }

    rc = virDomainGetVcpuPinInfo(d, dinfo->nrVirtCpu, cpumaps, maplen, VIR_DOMAIN_AFFECT_CONFIG);
    for (int i = 0; i < rc; i++) {
        (*vcpus)[i].vcpu = i;
        for (int j = 0; j < core_num; j++) {
            if (VIR_CPU_USABLE(cpumaps, maplen, i, j) > 0) {
                (*vcpus)[i].pcpu = j;
                break;
            }
        }
        (*vcpus)[i].hwp_cap_hi_perf = cores[(*vcpus)[i].pcpu].hwp_cap_hi_perf;
    }
    *count = rc;

    virDomainFree(d);
    free(dinfo);
    free(cpumaps);

    return 0;
}

static void clear_vcpu_info(struct vcpu_info *vcpus)
{
    free(vcpus);
}

const char *argp_program_version = "setup_shm 0.1";
static const char args_doc[] = "domain\n";
static const char argp_program_doc[] = "USAGE: sudo ./setup_shm domain\n";

struct arguments
{
    const char *domain_name;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    switch (key) {
    case ARGP_KEY_ARG:
        if (state->arg_num == 0)
            arguments->domain_name = arg;
        break;
    case ARGP_KEY_END:
        if (state->arg_num < 1)
            argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp_option opts[] = {
    {},
};

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .args_doc = args_doc,
    .doc = argp_program_doc,
};

int main(int argc, char *argv[])
{
    int err;
    struct core_info *core_map = NULL;
    int core_num = 0;
    struct vcpu_info *vcpu_map = NULL;
    int vcpu_num = 0;
    struct arguments arguments;

    err = argp_parse(&argp, argc, argv, 0, 0, &arguments);
    if (err)
        return err;

    _domain_name = arguments.domain_name;

    if (!is_hybrid_cpu()) {
        fprintf(stderr, "This is not an Intel hybrid CPU, thus meaningless to "
                        "run this tool\n");
        return EXIT_FAILURE;
    }

    if (access("/dev/cpu/0/msr", F_OK) == -1) {
        fprintf(stderr,
                "Cannot read MSR. Not root or forgot to modprobe msr?\n");
        return EXIT_FAILURE;
    }

    err = init_core_info(&core_map, &core_num);
    if (err) {
        fprintf(stderr, "Cannot get CPU info\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < core_num; i++) {
        err = get_msr_hwp_cap(&core_map[i]);
        if (err)
            return EXIT_FAILURE;
    }

    err = init_vcpu_info(&vcpu_map, &vcpu_num, core_map, core_num);
    if (err) {
        fprintf(stderr, "Cannot get domain %s 's vCPU info\n", _domain_name);
        return EXIT_FAILURE;
    }

    err = set_shm(vcpu_map, vcpu_num);
    if (err) {
        fprintf(stderr, "Failed to set ivshmem memory for KVM guests\n");
        return EXIT_FAILURE;
    }

    clear_core_info(&core_map);
    clear_vcpu_info(vcpu_map);

    fprintf(stdout, "Finished setup ivshmem device %s\n", _domain_name);
    fprintf(stdout, "Make sure the KVM guest has ivshmem device '%s' "
                    "set up, for example with libvirt:\n"
                    "    <devices>\n"
                    "        <shmem name='%s' role='peer'>\n"
                    "            <model type='ivshmem-plain'/>\n"
                    "            <size unit='M'>1</size>\n"
                    "        </shmem>\n"
                    "    </devices>\n", _domain_name, _domain_name);

    return EXIT_SUCCESS;
}
