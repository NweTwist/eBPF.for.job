#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

/* На части ядер "полное имя" — это flags=0 (дефолт), а флаг есть только для BASE_NAME */
#ifndef BPF_SYSCTL_FULLNAME
#define BPF_SYSCTL_FULLNAME 0
#endif

/* В твоей среде нет bpf_strcmp — делаем безопасное сравнение с фиксированным лимитом. */
static __always_inline int streq64(const char *a, const char *b)
{
#pragma unroll
    for (int i = 0; i < 64; i++) {
        char ca = a[i];
        char cb = b[i];

        if (ca != cb)
            return 0;
        if (ca == '\0')
            return 1;
    }
    return 0;
}

SEC("cgroup/sysctl")
int block_kernel_panic(struct bpf_sysctl *ctx)
{
    /* Verifier may treat helper arg as READ; keep stack buffer initialized. */
    char name[64] = {};
    int ret;

    if (!ctx->write)
        return 1;

    /* Если твоё ядро возвращает только basename, замени BPF_SYSCTL_FULLNAME на BPF_F_SYSCTL_BASE_NAME
       и сравнивай со строками "panic", "panic_on_oops", ... */
    ret = bpf_sysctl_get_name(ctx, name, sizeof(name), BPF_SYSCTL_FULLNAME);
    if (ret < 0)
        return 1;

    if (streq64(name, "kernel/panic") ||
        streq64(name, "kernel/panic_on_oops") ||
        streq64(name, "kernel/panic_on_warn") ||
        streq64(name, "kernel/hardlockup_panic") ||
        streq64(name, "kernel/softlockup_panic")) {
        return 0;
    }

    return 1;
}
