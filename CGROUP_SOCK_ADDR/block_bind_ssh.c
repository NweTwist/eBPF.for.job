#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

SEC("cgroup/bind4")
int deny_bind_any_ssh(struct bpf_sock_addr *ctx)
{
    __u32 ip = ctx->user_ip4;
    __u16 port = bpf_ntohs(ctx->user_port);

    if (ip == 0 && port == 22)
        return 0;
    return 1;
}
