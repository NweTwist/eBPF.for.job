#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("extension")
int ext_log(struct bpf_prog *ctx)
{
    bpf_printk("EXT: program invoked\n");
    return 0;
}
