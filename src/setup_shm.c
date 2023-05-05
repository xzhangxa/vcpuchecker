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
#include "cpu.h"

#define SHM_SIZE (1 * 1024 * 1024)

#define IVSHMEM_NAME "shm_cores"
#define QEMU_USER "libvirt-qemu"

static struct core_info *_core_map = NULL;
static int _core_num = 0;

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

int set_owner(int fd, const char *user, const char *group)
{
    struct passwd *pwd;
    struct group *grp;

    pwd = getpwnam(user);
    if (pwd == NULL)
        return -1;

    grp = getgrnam(group);
    if (grp == NULL)
        return -1;

    if (fchown(fd, pwd->pw_uid, grp->gr_gid) == -1)
        return -1;

    return 0;
}

int set_shm(struct core_info *cores, int count)
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

    fd = shm_open("/" IVSHMEM_NAME, O_RDWR | O_CREAT, 0640);
    if (fd == -1) {
        fprintf(stderr, "shm_open '%s' error: %s\n", IVSHMEM_NAME,
                strerror(errno));
        return -1;
    }

    if (ftruncate(fd, SHM_SIZE) == -1) {
        fprintf(stderr, "ftruncate '%s' error: %s\n", IVSHMEM_NAME,
                strerror(errno));
        return -1;
    }

    /*
    if (set_owner(fd, QEMU_USER, QEMU_USER)) {
        fprintf(stderr, "set owner '%s' error: %s\n", IVSHMEM_NAME,
                strerror(errno));
        return -1;
    }
    */

    p = mmap(NULL, SHM_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap error: %s\n", strerror(errno));
        return -1;
    }

    for (int i = 0; i < count; i++)
        *((uint8_t *)p + i) = cores[i].hwp_cap_hi_perf;

    if (munmap(p, SHM_SIZE) == -1) {
        fprintf(stderr, "munmap error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int err;

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

    err = init_core_info(&_core_map, &_core_num);
    if (err) {
        fprintf(stderr, "Cannot get CPU info\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < _core_num; i++) {
        err = get_msr_hwp_cap(&_core_map[i]);
        if (err)
            return EXIT_FAILURE;
    }

    err = set_shm(_core_map, _core_num);
    if (err) {
        fprintf(stderr, "Failed to set ivshmem memory for KVM guests\n");
        return EXIT_FAILURE;
    }

    clear_core_info(&_core_map);

    fprintf(stdout, "Finished setup ivshmem device %s\n", IVSHMEM_NAME);
    fprintf(stdout, "Make sure the KVM guest has ivshmem device 'shm_cores' "
                    "set up, for example with libvirt:\n"
                    "    <devices>\n"
                    "        <shmem name='" IVSHMEM_NAME "' role='peer'>\n"
                    "            <model type='ivshmem-plain'/>\n"
                    "            <size unit='M'>1</size>\n"
                    "        </shmem>\n"
                    "    </devices>\n");

    return EXIT_SUCCESS;
}
