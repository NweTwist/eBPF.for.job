#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";
SEC("cgroup/setsockopt")
int force_tcp_nodelay(struct bpf_sockopt *ctx)
{
    int one = 1;

    if (ctx->level == SOL _TCP && ctx->optname == TCP_NODELAY) {
        bpf_sockopt_set_optval(ctx, &one, sizeof(one));
        return 0;
    }
    return 0;
}
