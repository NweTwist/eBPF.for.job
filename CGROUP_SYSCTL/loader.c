/* Minimal loader for cgroup/sysctl (BPF_PROG_TYPE_CGROUP_SYSCTL)
 * Usage: loader_sysctl <cgroup_path> <bpf_object.o>
 * Build: gcc -O2 loader.c -o loader_sysctl -lbpf -lelf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

static volatile sig_atomic_t exiting = 0;
static void handle_sig(int sig) { exiting = 1; }

int main(int argc, char **argv)
{
    const char *cg_path;
    const char *obj_path;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    int cg_fd = -1, prog_fd = -1, err;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <cgroup_path> <bpf_object.o>\n", argv[0]);
        return 1;
    }

    cg_path = argv[1];
    obj_path = argv[2];

    cg_fd = open(cg_path, O_RDONLY | O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "open cgroup path failed\n");
        return 1;
    }

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object '%s'\n", obj_path);
        close(cg_fd);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        close(cg_fd);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (sec && strcmp(sec, "cgroup/sysctl") == 0) {
            prog_fd = bpf_program__fd(prog);
            break;
        }
    }

    if (prog_fd < 0) {
        /* fallback: take first program */
        prog = bpf_object__next_program(obj, NULL);
        if (prog)
            prog_fd = bpf_program__fd(prog);
    }

    if (prog_fd < 0) {
        fprintf(stderr, "couldn't find program fd in object\n");
        bpf_object__close(obj);
        close(cg_fd);
        return 1;
    }

    err = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SYSCTL, 0);
    if (err) {
        fprintf(stderr, "bpf_prog_attach failed\n");
        bpf_object__close(obj);
        close(cg_fd);
        return 1;
    }

    printf("Attached sysctl prog fd=%d to cgroup '%s' (fd=%d)\n", prog_fd, cg_path, cg_fd);
    printf("Send SIGINT/SIGTERM to detach and exit\n");

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    while (!exiting)
        pause();

    /* detach and cleanup */
    bpf_prog_detach2(prog_fd, cg_fd, BPF_CGROUP_SYSCTL);
    bpf_object__close(obj);
    close(cg_fd);
    printf("Detached and exiting\n");
    return 0;
}
