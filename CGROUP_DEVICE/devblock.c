#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Константы из UAPI (include/uapi/linux/bpf.h) для CGROUP_DEVICE:
#ifndef BPF_DEVCG_ACC_READ
#define BPF_DEVCG_ACC_READ   (1U << 0)
#endif
#ifndef BPF_DEVCG_ACC_WRITE
#define BPF_DEVCG_ACC_WRITE  (1U << 1)
#endif
#ifndef BPF_DEVCG_ACC_MKNOD
#define BPF_DEVCG_ACC_MKNOD  (1U << 2)
#endif
#ifndef BPF_DEVCG_DEV_BLOCK
#define BPF_DEVCG_DEV_BLOCK  (1U << 3)
#endif
#ifndef BPF_DEVCG_DEV_CHAR
#define BPF_DEVCG_DEV_CHAR   (1U << 4)
#endif

char _license[] SEC("license") = "GPL";

static __always_inline bool is_block_dev(__u32 access_type){
    return access_type & BPF_DEVCG_DEV_BLOCK;
}

static __always_inline bool is_rwm(__u32 access_type){
    return access_type & (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD);
}

SEC ("cgroup/dev")
int devblock (struct bpf_cgroup_dev_ctx *ctx)
{
#ifdef TEST_MODE
    if ((ctx->access_type & BPF_DEVCG_DEV_CHAR) && is_rwm(ctx->access_type)) {
        if (ctx->major == 1 && ctx->minor == 3){
            return 0;
        }
    }
    return 1;
#else
    if (is_block_dev(ctx->access_type) && is_rwm(ctx->access_type)){
        // Блокируем флоппи (major=2)
        if (ctx->major == 2) {
            return 0; // запретить
        }
    }
    return 1; // разрешить прочее
#endif
}

