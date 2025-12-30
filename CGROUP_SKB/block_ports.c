#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

static __always_inline bool in_range(__u16 port)
{
    return port >= 135 && port <= 139;
}

SEC("cgroup_skb/egress")
int block_135_139(struct __sk_buff *skb)
{
    __u8 first_byte = 0;
    __u8 ihl = 0;
    __u8 proto = 0;
    __u16 sport = 0, dport = 0;

    if (bpf_skb_load_bytes(skb, 0, &first_byte, sizeof(first_byte)) < 0)
        return 1;

    if ((first_byte >> 4) != 4)
        return 1;

    ihl = (first_byte & 0x0F) * 4;
    if (ihl < 20)
        return 1;

    if (bpf_skb_load_bytes(skb, 9, &proto, sizeof(proto)) < 0)
        return 1;

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return 1;

    __u16 net_sport = 0, net_dport = 0;
    if (bpf_skb_load_bytes(skb, ihl + 0, &net_sport, sizeof(net_sport)) < 0)
        return 1;
    if (bpf_skb_load_bytes(skb, ihl + 2, &net_dport, sizeof(net_dport)) < 0)
        return 1;

    sport = bpf_ntohs(net_sport);
    dport = bpf_ntohs(net_dport);

    if (in_range(sport) || in_range(dport))
        return 0;

    return 1;
}
