#ifndef QEMU_HVF_H
#define QEMU_HVF_H

/* defaults from kernel source */
#define HVF_KVM_MAX_VCPUS 255
#define HVF_KVM_SOFT_MAX_VCPUS 160
#define HVF_KVM_USER_MEM_SLOTS 509

int hvf_qemu_open(KVMState *s);
int hvf_qemu_close(KVMState *s);
struct kvm_run* hvf_get_kvm_run(int fd);
uint32_t hvf_get_hvf_id(int fd);
int hvf_madvise_dontfork(void *addr, size_t len, int dontfork);

#endif
