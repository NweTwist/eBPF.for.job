#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("cgroup/sock")
int allow_only_tcp(struct bpf_sock *sk)
{
    int allow = 0;                  // по умолчанию запрет
    if (sk->protocol == IPPROTO_TCP)
        allow = 1;                  // разрешить только TCP
    return allow;                   // 0/1
}
