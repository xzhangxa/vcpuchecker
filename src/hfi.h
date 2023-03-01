#ifndef _HFI_H_
#define _HFI_H_

#ifdef __cplusplus
extern "C" {
#endif

struct perf_cap {
    int cpu;
    int perf;
    int eff;
};

typedef void (*hfi_callback)(struct perf_cap *cap);

extern int hfi_init(hfi_callback hfi_cb);
extern int hfi_recvmsg(void);

#ifdef __cplusplus
}
#endif

#endif /* _HFI_H_ */
