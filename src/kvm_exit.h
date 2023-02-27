#ifndef _KVM_EXIT_H_
#define _KVM_EXIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "vc_event.h"

typedef void (*kvm_exit_callback)(struct kvm_exit_info *);

extern int bpf_init(kvm_exit_callback callback);
extern int bpf_rb_poll(int timeout_ms);
extern void bpf_exit(void);
extern const char *vmx_exit_str(uint32_t exit_reason);

#ifdef __cplusplus
}
#endif

#endif /* _KVM_EXIT_H_ */
