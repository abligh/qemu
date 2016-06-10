/*
 * QEMU HVM support
 *
 * Copyright Alex Bligh, 2016
 *           Red Hat, Inc. 2008
 *
 * Authors:
 *  Alex Bligh <alex@alex.org.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "qemu-common.h"
#include "qemu/atomic.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/mmap-alloc.h"
#include "sysemu/kvm_int.h"
#include "trace.h"
#include "hw/irq.h"
#include "sysemu/kvm.h"
#include "kvmstate.h"
#include "hvf.h"

#include <sys/sysctl.h>
#include <mach/vm_inherit.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <Hypervisor/hv_error.h>

typedef enum {
    HVF_FDT_KVM,
    HVF_FDT_VM,
    HVF_FDT_VCPU
} hvf_fdt_e;

typedef struct hvf_fd_rec {
    void *mem;
    struct kvm_run *kvm_run;
    int fd;
    hv_vcpuid_t hvf_id;
    hvf_fdt_e type;
} hvf_fd_rec;

static GHashTable *hvf_fd_map;
static pthread_mutex_t hvf_fd_map_mutex = PTHREAD_MUTEX_INITIALIZER;

#define HVF_VCPU_MMAP_SIZE (( (sizeof(struct kvm_run) + (128 * PAGE_SIZE)) + PAGE_SIZE-1 ) & ~(PAGE_SIZE-1))

#define PPRO_FEATURES (CPUID_FP87 | CPUID_DE | CPUID_PSE | CPUID_TSC | \
                       CPUID_MSR | CPUID_MCE | CPUID_CX8 | CPUID_PGE | CPUID_CMOV | \
                       CPUID_PAT | CPUID_FXSR | CPUID_MMX | CPUID_SSE | CPUID_SSE2 | \
                       CPUID_PAE | CPUID_SEP | CPUID_APIC)

#define MSR_KERNEL_GS_BASE      0xc0000102 /* SwapGS GS shadow */
#define MSR_SYSCALL_MASK        0xc0000084 /* EFLAGS mask for syscall */
#define MSR_IA32_CR_PAT         0x00000277

/* taken from KVM's msrs_to_save */
static uint32_t msr_list[] = {
    MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
    MSR_STAR,
    MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
    MSR_IA32_TSC, MSR_IA32_CR_PAT, MSR_VM_HSAVE_PA,
    MSR_IA32_FEATURE_CONTROL, MSR_IA32_BNDCFGS, MSR_TSC_AUX,
};

static struct kvm_cpuid_entry2 hvf_cpuids[]= {
    /* For the time being, take this from the kvm64 definition */
    { .flags = 0, .function = 0x00, .index = 0,
      .eax = 0x0d,
      .ebx = CPUID_VENDOR_INTEL_1,
      .edx = CPUID_VENDOR_INTEL_2,
      .ecx = CPUID_VENDOR_INTEL_3
    },
    { .flags = 0, .function = 0x01, .index = 0,
      .eax = 1 | 6<<4 | 15<<8,
      .ebx = CPUID_VENDOR_INTEL_1,
      .edx = PPRO_FEATURES | CPUID_VME | CPUID_MTRR | CPUID_CLFLUSH | CPUID_MCA | CPUID_PSE36,
      .ecx = CPUID_EXT_SSE3 | CPUID_EXT_CX16
    },
    { .flags = 0, .function = 0x080000000, .index = 0,
      .eax = 0x80000008,
    },
    { .flags = 0, .function = 0x080000001, .index = 0,
      .edx = CPUID_EXT2_LM | CPUID_EXT2_SYSCALL | CPUID_EXT2_NX,
      .ecx = 0
    }
};
    
static void hvf_fd_map_ensure() {
    if (!hvf_fd_map) {
        hvf_fd_map = g_hash_table_new(g_int_hash, g_int_equal);
    }
}

static void hvf_fd_map_insert (hvf_fd_rec *rec) {
    pthread_mutex_lock(&hvf_fd_map_mutex);
    hvf_fd_map_ensure();
    g_hash_table_insert(hvf_fd_map, &rec->fd, rec);
    pthread_mutex_unlock(&hvf_fd_map_mutex);
} 

static hvf_fd_rec* hvf_fd_map_delete (int fd) {
    hvf_fd_rec *r;
    pthread_mutex_lock(&hvf_fd_map_mutex);
    hvf_fd_map_ensure();
    r = g_hash_table_lookup(hvf_fd_map, &fd);
    if (r) {
        g_hash_table_remove(hvf_fd_map, &fd);
    }
    pthread_mutex_unlock(&hvf_fd_map_mutex);
    return r;
}

static hvf_fd_rec* hvf_fd_map_get (int fd) {
    hvf_fd_rec *r;
    pthread_mutex_lock(&hvf_fd_map_mutex);
    hvf_fd_map_ensure();
    r = g_hash_table_lookup(hvf_fd_map, &fd);
    pthread_mutex_unlock(&hvf_fd_map_mutex);
    return r;
} 

static hvf_fd_rec* hvf_fd_rec_new (hvf_fdt_e type) {
    hvf_fd_rec *rec;
    rec = g_malloc0(sizeof(hvf_fd_rec));
    rec->fd = qemu_open("/dev/null", O_RDWR);
    rec->type = type;
    return rec;
}

static void hvf_fd_rec_free (hvf_fd_rec *rec) {
    if (!rec) {
        return;
    }
    if (rec->mem) {
        g_free(rec->mem);
        rec->mem = 0;
    }
    if (rec->kvm_run) {
        qemu_ram_munmap(rec->kvm_run, HVF_VCPU_MMAP_SIZE);
        rec->kvm_run = 0;
    }
    if (rec->fd >= 0) {
        close (rec->fd);
        rec->fd = -1;
    }
}

static int hvf_kvm_check_extension(int n) {
    switch (n) {

    case KVM_CAP_NR_VCPUS:
    case KVM_CAP_MAX_VCPUS:
        return 16;
    case KVM_CAP_USER_MEMORY:
    case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
    case KVM_CAP_SET_TSS_ADDR:
    case KVM_CAP_EXT_CPUID:
    case KVM_CAP_MP_STATE:
    case KVM_CAP_XSAVE:
        return 1;
    case KVM_CAP_NR_MEMSLOTS:
        return HVF_KVM_USER_MEM_SLOTS;
        
    default:
        fprintf(stderr, "*** Check unknown extension %d\n", n);
        return -EINVAL;
    }
}

static int hvf_kvm_create_vm(int type) {
    hvf_fd_rec *rec = NULL;
    
    if (type != 0) {
        return -EINVAL;
    }

    if (hv_vm_create(HV_VM_DEFAULT) != HV_SUCCESS) {
        return -EINVAL;
    }
    
    rec = hvf_fd_rec_new(HVF_FDT_VM);

    hvf_fd_map_insert(rec);
    return rec->fd;
}

static int hvf_kvm_create_vcpu(int id) {
    hvf_fd_rec *rec = NULL;
    uint32_t nmsrs = sizeof(msr_list) / sizeof(uint32_t);
    uint32_t i;
    hv_return_t ret;
    
    rec = hvf_fd_rec_new(HVF_FDT_VCPU);

    if (hv_vcpu_create(&rec->hvf_id, HV_VCPU_DEFAULT) != HV_SUCCESS) {
        return -EINVAL;
    }

    for (i = 0 ; i<nmsrs; i++) {
        ret = hv_vcpu_enable_native_msr(rec->hvf_id, msr_list[i], 1);
        if (!ret) {
            fprintf(stderr, "*** Could not enable MSR %08x (item %d)\n", msr_list[i], i);
        }
    }

    rec->kvm_run = qemu_ram_mmap(-1, HVF_VCPU_MMAP_SIZE, PAGE_SIZE, false);
    
    hvf_fd_map_insert(rec);
    return rec->fd;
}

static int hvf_kvm_set_user_memory_region(KVMState *s, struct kvm_userspace_memory_region *r) {
    if (r->slot > HVF_KVM_USER_MEM_SLOTS) {
        return -EINVAL;
    }

    if (s->hvf_slot[r->slot].memory_size) {
        if (r->memory_size && s->hvf_slot[r->slot].memory_size != r->memory_size) {
            return -EINVAL;
        }
        if (hv_vm_unmap (s->hvf_slot[r->slot].guest_phys_addr, s->hvf_slot[r->slot].memory_size) != HV_SUCCESS) {
            return -ENOENT;
        }
        memset(&s->hvf_slot[r->slot].memory_size, 0, sizeof(struct kvm_userspace_memory_region));
    }
    if (!r->memory_size)
        return 0;
    hv_memory_flags_t flags = HV_MEMORY_READ | HV_MEMORY_EXEC | (r->flags & KVM_MEM_READONLY);
    if (hv_vm_map ((hv_uvaddr_t)r->userspace_addr, r->guest_phys_addr, r->memory_size, flags) != HV_SUCCESS) {
        return -ENOENT;
    }
    s->hvf_slot[r->slot] = *r;
    return 0;
}

static int hvf_kvm_run(CPUState *cpu) {
    hv_return_t ret;
    int hvf_id = cpu->hvf_id;
    // struct kvm_run *kvm_run = cpu->kvm_run;
    int stop = 0;
    do {
        uint64_t exit_reason;
        ret = hv_vcpu_run(hvf_id);
        if (ret != HV_SUCCESS) {
            fprintf(stderr, "*** hv_vcpu_run returned %x\n", ret);
            return -EINVAL;
        }
        ret = hv_vmx_vcpu_read_vmcs(hvf_id, VMCS_RO_EXIT_REASON, &exit_reason);
        exit_reason &= 0xffff;
        if (ret != HV_SUCCESS) {
            fprintf(stderr, "*** hv_vcpu_read_vmcs returned %x\n", ret);
            return -EINVAL;
        }
        switch (exit_reason) {
        default:
            fprintf(stderr, "*** unhandled exit reason %llu\n", exit_reason);
        }
    } while (!stop);
    
    return 0;
}

static int hvf_kvm_set_regs(CPUState *cpu, struct kvm_regs *r) {
    int hvf_id = cpu->hvf_id;
    hv_vcpu_write_register(hvf_id, HV_X86_RAX, r->rax);
    hv_vcpu_write_register(hvf_id, HV_X86_RBX, r->rbx);
    hv_vcpu_write_register(hvf_id, HV_X86_RCX, r->rcx);
    hv_vcpu_write_register(hvf_id, HV_X86_RDX, r->rdx);
    hv_vcpu_write_register(hvf_id, HV_X86_RSI, r->rsi);
    hv_vcpu_write_register(hvf_id, HV_X86_RDI, r->rdi);
    hv_vcpu_write_register(hvf_id, HV_X86_RSP, r->rsp);
    hv_vcpu_write_register(hvf_id, HV_X86_RBP, r->rbp);
    hv_vcpu_write_register(hvf_id, HV_X86_R8 , r->r8 );
    hv_vcpu_write_register(hvf_id, HV_X86_R9 , r->r9 );
    hv_vcpu_write_register(hvf_id, HV_X86_R10, r->r10);
    hv_vcpu_write_register(hvf_id, HV_X86_R11, r->r11);
    hv_vcpu_write_register(hvf_id, HV_X86_R12, r->r12);
    hv_vcpu_write_register(hvf_id, HV_X86_R13, r->r13);
    hv_vcpu_write_register(hvf_id, HV_X86_R14, r->r14);
    hv_vcpu_write_register(hvf_id, HV_X86_R15, r->r15);
    hv_vcpu_write_register(hvf_id, HV_X86_RIP, r->rip);
    hv_vcpu_write_register(hvf_id, HV_X86_RFLAGS, r->rflags);
    return 0;
}

static int hvf_kvm_get_regs(CPUState *cpu, struct kvm_regs *r) {
    int hvf_id = cpu->hvf_id;
    hv_vcpu_read_register(hvf_id, HV_X86_RAX, &r->rax);
    hv_vcpu_read_register(hvf_id, HV_X86_RBX, &r->rbx);
    hv_vcpu_read_register(hvf_id, HV_X86_RCX, &r->rcx);
    hv_vcpu_read_register(hvf_id, HV_X86_RDX, &r->rdx);
    hv_vcpu_read_register(hvf_id, HV_X86_RSI, &r->rsi);
    hv_vcpu_read_register(hvf_id, HV_X86_RDI, &r->rdi);
    hv_vcpu_read_register(hvf_id, HV_X86_RSP, &r->rsp);
    hv_vcpu_read_register(hvf_id, HV_X86_RBP, &r->rbp);
    hv_vcpu_read_register(hvf_id, HV_X86_R8 , &r->r8 );
    hv_vcpu_read_register(hvf_id, HV_X86_R9 , &r->r9 );
    hv_vcpu_read_register(hvf_id, HV_X86_R10, &r->r10);
    hv_vcpu_read_register(hvf_id, HV_X86_R11, &r->r11);
    hv_vcpu_read_register(hvf_id, HV_X86_R12, &r->r12);
    hv_vcpu_read_register(hvf_id, HV_X86_R13, &r->r13);
    hv_vcpu_read_register(hvf_id, HV_X86_R14, &r->r14);
    hv_vcpu_read_register(hvf_id, HV_X86_R15, &r->r15);
    hv_vcpu_read_register(hvf_id, HV_X86_RIP, &r->rip);
    hv_vcpu_read_register(hvf_id, HV_X86_RFLAGS, &r->rflags);
    return 0;
}

static int hvf_kvm_set_sregs(CPUState *cpu, struct kvm_sregs *r) {
    int hvf_id = cpu->hvf_id;
    hv_vcpu_write_register(hvf_id, HV_X86_CS, r->cs.base);
    hv_vcpu_write_register(hvf_id, HV_X86_DS, r->ds.base);
    hv_vcpu_write_register(hvf_id, HV_X86_ES, r->es.base);
    hv_vcpu_write_register(hvf_id, HV_X86_FS, r->fs.base);
    hv_vcpu_write_register(hvf_id, HV_X86_GS, r->gs.base);
    hv_vcpu_write_register(hvf_id, HV_X86_SS, r->ss.base);

    hv_vcpu_write_register(hvf_id, HV_X86_TR, r->tr.selector);
    hv_vcpu_write_register(hvf_id, HV_X86_TSS_BASE, r->tr.base);
    hv_vcpu_write_register(hvf_id, HV_X86_TSS_LIMIT, r->tr.limit);
    //hv_vcpu_write_register(hvf_id, HV_X86_TSS_AR, r->tr.ar); // ??

    hv_vcpu_write_register(hvf_id, HV_X86_LDTR, r->ldt.selector);
    hv_vcpu_write_register(hvf_id, HV_X86_LDT_BASE, r->ldt.base);
    hv_vcpu_write_register(hvf_id, HV_X86_LDT_LIMIT, r->ldt.limit);
    //hv_vcpu_write_register(hvf_id, HV_X86_LDT_AR, r->ldt.ar); // ??

    hv_vcpu_write_register(hvf_id, HV_X86_GDT_BASE, r->gdt.base);
    hv_vcpu_write_register(hvf_id, HV_X86_GDT_LIMIT, r->gdt.limit);
    hv_vcpu_write_register(hvf_id, HV_X86_IDT_BASE, r->idt.base);
    hv_vcpu_write_register(hvf_id, HV_X86_IDT_LIMIT, r->idt.limit);

    hv_vcpu_write_register(hvf_id, HV_X86_CR0, r->cr0);
    hv_vcpu_write_register(hvf_id, HV_X86_CR2, r->cr2);
    hv_vcpu_write_register(hvf_id, HV_X86_CR3, r->cr3);
    hv_vcpu_write_register(hvf_id, HV_X86_CR4, r->cr4);
    hv_vcpu_write_register(hvf_id, HV_X86_TPR, r->cr8); // CR8 == TPR

    hv_vcpu_write_msr(hvf_id, MSR_EFER, r->efer); /* this is an MSR */
    hv_vcpu_write_msr(hvf_id, MSR_IA32_APICBASE, r->apic_base); /* this is an MSR */
    // should this in fact use hv_vmx_vcpu_set_apic_address? instead? as well?
    // TODO: interrupt bitmaps in interrupt_bitmap
    return 0;
}

static int hvf_kvm_get_sregs(CPUState *cpu, struct kvm_sregs *r) {
    int hvf_id = cpu->hvf_id;
    uint64_t n;
    hv_vcpu_read_register(hvf_id, HV_X86_CS, &r->cs.base);
    hv_vcpu_read_register(hvf_id, HV_X86_DS, &r->ds.base);
    hv_vcpu_read_register(hvf_id, HV_X86_ES, &r->es.base);
    hv_vcpu_read_register(hvf_id, HV_X86_FS, &r->fs.base);
    hv_vcpu_read_register(hvf_id, HV_X86_GS, &r->gs.base);
    hv_vcpu_read_register(hvf_id, HV_X86_SS, &r->ss.base);

    hv_vcpu_read_register(hvf_id, HV_X86_TR, &n);
    r->tr.selector = n;
    hv_vcpu_read_register(hvf_id, HV_X86_TSS_BASE, &r->tr.base);
    hv_vcpu_read_register(hvf_id, HV_X86_TSS_LIMIT, &n);
    r->tr.limit = n;
    //hv_vcpu_read_register(hvf_id, HV_X86_TSS_AR, &r->tr.ar); // ??

    hv_vcpu_read_register(hvf_id, HV_X86_LDTR, &n);
    r->ldt.selector = n;
    hv_vcpu_read_register(hvf_id, HV_X86_LDT_BASE, &r->ldt.base);
    hv_vcpu_read_register(hvf_id, HV_X86_LDT_LIMIT, &n);
    r->ldt.limit = n;
    //hv_vcpu_read_register(hvf_id, HV_X86_LDT_AR, &r->ldt.ar); // ??

    hv_vcpu_read_register(hvf_id, HV_X86_GDT_BASE, &r->gdt.base);
    hv_vcpu_read_register(hvf_id, HV_X86_GDT_LIMIT, &n);
    r->gdt.limit = n;
    hv_vcpu_read_register(hvf_id, HV_X86_IDT_BASE, &r->idt.base);
    hv_vcpu_read_register(hvf_id, HV_X86_IDT_LIMIT, &n);
    r->idt.limit = n;

    hv_vcpu_read_register(hvf_id, HV_X86_CR0, &r->cr0);
    hv_vcpu_read_register(hvf_id, HV_X86_CR2, &r->cr2);
    hv_vcpu_read_register(hvf_id, HV_X86_CR3, &r->cr3);
    hv_vcpu_read_register(hvf_id, HV_X86_CR4, &r->cr4);
    hv_vcpu_read_register(hvf_id, HV_X86_TPR, &r->cr8); // CR8 == TPR

    hv_vcpu_read_msr(hvf_id, MSR_EFER, &r->efer); /* this is an MSR */
    hv_vcpu_read_msr(hvf_id, MSR_IA32_APICBASE, &r->apic_base); /* this is an MSR */
    /* TODO: interrupt bitmaps in interrupt_bitmap */
    return 0;
}

static int hvf_kvm_set_msrs(CPUState *cpu, struct kvm_msrs *r) {
    int hvf_id = cpu->hvf_id;
    uint32_t i;
    for (i = 0 ; i < r->nmsrs; i++) {
        hv_vcpu_write_msr(hvf_id, r->entries[i].index, r->entries[i].data);
    }
    return r->nmsrs; /* documentation is wrong on return value */
}

static int hvf_kvm_get_msrs(CPUState *cpu, struct kvm_msrs *r) {
    int hvf_id = cpu->hvf_id;
    uint32_t i;
    for (i = 0 ; i < r->nmsrs; i++) {
        hv_vcpu_read_msr(hvf_id, r->entries[i].index, &r->entries[i].data);
    }
    return r->nmsrs; /* documentation is wrong on return value */
}

static int hvf_kvm_set_xsave(CPUState *cpu, struct kvm_xsave *r) {
    int hvf_id = cpu->hvf_id;
    hv_vcpu_write_fpstate(hvf_id, r, sizeof(struct kvm_xsave));
    return 0;
}

static int hvf_kvm_get_xsave(CPUState *cpu, struct kvm_xsave *r) {
    int hvf_id = cpu->hvf_id;
    hv_vcpu_read_fpstate(hvf_id, r, sizeof(struct kvm_xsave));
    return 0;
}

struct kvm_run* hvf_get_kvm_run(int fd) {
    hvf_fd_rec *rec;
    rec = hvf_fd_map_get(fd);
    if (!rec) {
        return NULL;
    }
    return rec->kvm_run;
}

uint32_t hvf_get_hvf_id(int fd) {
    hvf_fd_rec *rec;
    rec = hvf_fd_map_get(fd);
    if (!rec) {
        return -ENOENT;
    }
    return rec->hvf_id;
}

int kvm_ioctl(KVMState *s, int type, ...)
{
    int n;
    void *arg;
    va_list ap, ap2;

    va_start(ap, type);
    va_copy(ap2, ap);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_ioctl(type, arg);

    switch (type) {
    case (int)KVM_GET_API_VERSION:
        return KVM_API_VERSION;
    case (int)KVM_CHECK_EXTENSION:
        n = va_arg(ap2, int);
        va_end(ap2);
        return hvf_kvm_check_extension(n);
    case (int)KVM_CREATE_VM:
        n = va_arg(ap2, int);
        va_end(ap2);
        return hvf_kvm_create_vm(n);
    case (int)KVM_GET_SUPPORTED_CPUID:
    {
        __u32 i;
        struct kvm_cpuid2 *l;
        size_t nsupported = sizeof(hvf_cpuids) / sizeof(hvf_cpuids[0]);
        l = va_arg(ap2, struct kvm_cpuid2*);
        if (l->nent < nsupported) {
            return -E2BIG;
        }
        for (i = 0; i < nsupported; i++) {
            memcpy(&l->entries[i], &hvf_cpuids[i], sizeof(struct kvm_cpuid_entry2));
        }
        l->nent = nsupported;
        return 0;
    }
        
    case (int)KVM_GET_MSR_INDEX_LIST:
    {
        struct kvm_msr_list *l;
        uint32_t nmsrs = sizeof(msr_list) / sizeof(uint32_t);
        l = va_arg(ap2, struct kvm_msr_list*);
        va_end(ap2);
        if (l->nmsrs < nmsrs) {
            l->nmsrs = nmsrs;
            return -E2BIG;
        }
        l->nmsrs = nmsrs;
        memcpy(l->indices, msr_list, nmsrs * sizeof(uint32_t));
        return 0;
    }
    case KVM_GET_VCPU_MMAP_SIZE:
        return HVF_VCPU_MMAP_SIZE;
    default:
        fprintf(stderr, "*** Unknown kvm_ioctl %x\n", type);
        return -EINVAL;
    }

    return -EINVAL;
}

int kvm_vm_ioctl(KVMState *s, int type, ...)
{
    void *arg;
    va_list ap, ap2;
    int n;
    
    va_start(ap, type);
    va_copy(ap2, ap);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vm_ioctl(type, arg);

    switch (type) {
    case (int)KVM_SET_TSS_ADDR:
        return 0;
    case (int)KVM_CREATE_VCPU:
        n = va_arg(ap2, int);
        va_end(ap2);
        return hvf_kvm_create_vcpu(n);
    case (int)KVM_SET_USER_MEMORY_REGION:
    {
        struct kvm_userspace_memory_region *r;
        r = va_arg(ap2,  struct kvm_userspace_memory_region *);
        va_end(ap2);
        return hvf_kvm_set_user_memory_region(s, r);
    }
    default:
        fprintf(stderr, "*** Unknown kvm_vm_ioctl %x\n", type);
        return -EINVAL;
    }

    return -EINVAL;
}

int kvm_vcpu_ioctl(CPUState *cpu, int type, ...)
{
    void *arg;
    va_list ap, ap2;

    va_start(ap, type);
    va_copy(ap2, ap);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vcpu_ioctl(cpu->cpu_index, type, arg);

    switch (type) {
    case (int)KVM_SET_CPUID2:
    case (int)KVM_SET_SIGNAL_MASK:
        return 0;
    case (int)KVM_SET_REGS:
    {
        struct kvm_regs *r;
        r = va_arg(ap2, struct kvm_regs*);
        va_end(ap2);
        return hvf_kvm_set_regs(cpu, r);
    }
    case (int)KVM_GET_REGS:
    {
        struct kvm_regs *r;
        r = va_arg(ap2, struct kvm_regs*);
        va_end(ap2);
        return hvf_kvm_get_regs(cpu, r);
    }
    case (int)KVM_SET_SREGS:
    {
        struct kvm_sregs *r;
        r = va_arg(ap2, struct kvm_sregs*);
        va_end(ap2);
        return hvf_kvm_set_sregs(cpu, r);
    }
    case (int)KVM_GET_SREGS:
    {
        struct kvm_sregs *r;
        r = va_arg(ap2, struct kvm_sregs*);
        va_end(ap2);
        return hvf_kvm_get_sregs(cpu, r);
    }
    case (int)KVM_SET_MSRS:
    {
        struct kvm_msrs *r;
        r = va_arg(ap2, struct kvm_msrs*);
        va_end(ap2);
        return hvf_kvm_set_msrs(cpu, r);
    }
    case (int)KVM_GET_MSRS:
    {
        struct kvm_msrs *r;
        r = va_arg(ap2, struct kvm_msrs*);
        va_end(ap2);
        return hvf_kvm_get_msrs(cpu, r);
    }
    case (int)KVM_SET_XSAVE:
    {
        struct kvm_xsave *r;
        r = va_arg(ap2, struct kvm_xsave*);
        va_end(ap2);
        return hvf_kvm_set_xsave(cpu, r);
    }
    case (int)KVM_GET_XSAVE:
    {
        struct kvm_xsave *r;
        r = va_arg(ap2, struct kvm_xsave*);
        va_end(ap2);
        return hvf_kvm_get_xsave(cpu, r);
    }
    case (int)KVM_GET_MP_STATE:
    {
        struct kvm_mp_state *r;
        r = va_arg(ap2, struct kvm_mp_state*);
        va_end(ap2);
        r->mp_state = KVM_MP_STATE_RUNNABLE;
        return 0;
    }
    case (int) KVM_SET_MP_STATE:
        return 0;
    case (int) KVM_RUN:
        return hvf_kvm_run(cpu);
    case (int)KVM_SET_FPU:
    case (int)KVM_GET_FPU:
        fprintf(stderr, "*** KVM_{GET,SET}_FPU kvm_vcpu_ioctl should not be called with KVM_CAP_XSAVE%x\n", type);
        return -EINVAL;
    default:
        fprintf(stderr, "*** Unknown kvm_vcpu_ioctl %x\n", type);
        return -EINVAL;
    }

    return -EINVAL;
}

int kvm_device_ioctl(int fd, int type, ...)
{
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_device_ioctl(fd, type, arg);

    errno = EINVAL;
    fprintf(stderr, "*** Unknown kvm_device_ioctl %x\n", type);

    return -errno;
}

int hvf_qemu_open(KVMState *s)
{
    int ret;
    int32_t support = 0;
    size_t len = sizeof(support);
    hvf_fd_rec *rec;
    
    if (sysctlbyname("kern.hv_support", &support, &len, NULL, 0) < 0) {
        ret = -errno;
        fprintf(stderr, "Could not access sysctl: %s\n", strerror(-ret));
        return ret;
    }

    if (support != 1) {
        ret = -EINVAL;
        fprintf(stderr, "OS-X does not have Hypervisor.Framework support enabled\n");
        return ret;
    }
    
    rec = hvf_fd_rec_new(HVF_FDT_KVM);

    hvf_fd_map_insert(rec);
    s->fd = rec->fd;
    return 0;
}

int hvf_qemu_close(KVMState *s)
{
    hvf_fd_rec *rec;
    if (s->fd == -1) {
        return 0;
    }
    
    rec = hvf_fd_map_delete(s->fd);
    if (!rec) {
        return 0;
    }
    hvf_fd_rec_free(rec);
    
    return 0;
}

int hvf_madvise_dontfork(void *addr, size_t len, int dontfork)
{
    return minherit(addr, len, dontfork?VM_INHERIT_NONE:VM_INHERIT_COPY);
}
