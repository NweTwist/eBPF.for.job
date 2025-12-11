#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

static __always_inline bool is_block_dev(__u32 access_type){
    return access_type & BPF_DEVCG_DEV_BLOCK;
}

static __always_inline bool is_char_dev (__u32 access_type){
    return access_type & BPF_DEVCG_DEV_CHAR;
}

static __always_inline bool is_rwm(__u32 access_type){
    return access_type & (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD);
}

SEC ("cgroup/dev")

int devblock (struct bpf_cgroup_dev_ctx *ctx)
{

#ifdef TEST_MODE
    if (is_char_dev(ctx->access_type) && is_rwm(ctx->access_type)) {

        if (ctx->major == 1 && ctx->minor == 3){
            return 0;
        }
    }
    
    return 1;

#else
    if (is_block_dev(ctx->access_type) && is_rwm(ctx->access_type)){
        if(ctx->major==0 || (ctx->major >= 65 && ctx->major <= 71) || ctx->major == 259) {
            return 0; 
        }
    }
    return 1;

#endif
}

