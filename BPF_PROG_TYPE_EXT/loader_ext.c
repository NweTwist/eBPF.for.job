#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

// Fallback for older UAPI headers that don't define BPF_PROG_TYPE_EXT.
// Upstream enum value: 28 (after BPF_PROG_TYPE_STRUCT_OPS=27).
#ifndef BPF_PROG_TYPE_EXT
#define BPF_PROG_TYPE_EXT ((enum bpf_prog_type)28)
#endif

#ifndef BPF_ATTACH_TYPE_UNSPEC
#define BPF_ATTACH_TYPE_UNSPEC 0
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s <target_bpf_object.o> <ext_bpf_object.o> [--pin-link <path>]\n"
            "  %s --target-id <id> <ext_bpf_object.o> [--pin-link <path>]\n",
            prog, prog);
}

static struct bpf_program *find_ext_prog(struct bpf_object *obj)
{
    struct bpf_program *p;

    bpf_object__for_each_program(p, obj) {
        const char *sec = bpf_program__section_name(p);
        if (sec && strcmp(sec, "extension") == 0)
            return p;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *target_obj_path = NULL;
    const char *ext_obj_path = NULL;
    const char *pin_link_path = NULL;
    int target_id = -1;

    struct bpf_object *target_obj = NULL;
    struct bpf_object *ext_obj = NULL;
    struct bpf_program *ext_prog = NULL;

    int target_prog_fd = -1;
    int err;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--target-id") == 0) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        target_id = atoi(argv[2]);
        ext_obj_path = argv[3];

        for (int i = 4; i < argc; i++) {
            if (!strcmp(argv[i], "--pin-link") && i + 1 < argc) {
                pin_link_path = argv[++i];
            }
        }
    } else {
        target_obj_path = argv[1];
        ext_obj_path = argv[2];

        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "--pin-link") && i + 1 < argc) {
                pin_link_path = argv[++i];
            }
        }
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    if (target_id >= 0) {
        target_prog_fd = bpf_prog_get_fd_by_id((__u32)target_id);
        if (target_prog_fd < 0) {
            fprintf(stderr, "failed to get target prog fd by id=%d\n", target_id);
            return 1;
        }
    } else {
        target_obj = bpf_object__open_file(target_obj_path, NULL);
        err = libbpf_get_error(target_obj);
        if (err) {
            fprintf(stderr, "failed to open target BPF object '%s': %d (%s)\n",
                    target_obj_path, err, strerror(-err));
            return 1;
        }
        err = bpf_object__load(target_obj);
        if (err) {
            fprintf(stderr, "failed to load target BPF object: %d (%s) errno=%d (%s)\n",
                    err, strerror(-err), errno, strerror(errno));
            bpf_object__close(target_obj);
            return 1;
        }
        target_prog_fd = pick_first_prog_fd(target_obj);
        if (target_prog_fd < 0) {
            fprintf(stderr, "couldn't find a program in target object\n");
            bpf_object__close(target_obj);
            return 1;
        }
    }

    ext_obj = bpf_object__open_file(ext_obj_path, NULL);
    err = libbpf_get_error(ext_obj);
    if (err) {
        fprintf(stderr, "failed to open EXT BPF object '%s': %d (%s)\n",
                ext_obj_path, err, strerror(-err));
        return 1;
    }

    ext_prog = find_ext_prog(ext_obj);
    if (!ext_prog) {
        fprintf(stderr, "couldn't find SEC(\"extension\") program in ext object\n");
        bpf_object__close(ext_obj);
        return 1;
    }

    bpf_program__set_type(ext_prog, BPF_PROG_TYPE_EXT);

    err = bpf_program__set_attach_target(ext_prog, target_prog_fd, NULL);
    if (err) {
        fprintf(stderr, "bpf_program__set_attach_target failed: %d (%s)\n", err, strerror(-err));
        bpf_object__close(ext_obj);
        return 1;
    }

    err = bpf_object__load(ext_obj);
    if (err) {
        fprintf(stderr, "failed to load EXT BPF object: %d (%s) errno=%d (%s)\n",
                err, strerror(-err), errno, strerror(errno));
        bpf_object__close(ext_obj);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach(ext_prog);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "bpf_program__attach failed: %d (%s)\n", err, strerror(-err));
        bpf_object__close(ext_obj);
        return 1;
    }

    if (pin_link_path) {
        err = bpf_link__pin(link, pin_link_path);
        if (err) {
            fprintf(stderr, "bpf_link__pin('%s') failed: %d (%s)\n",
                    pin_link_path, err, strerror(-err));
            bpf_link__destroy(link);
            bpf_object__close(ext_obj);
            return 1;
        }
        fprintf(stderr, "Pinned link at %s\n", pin_link_path);
        /* OK to exit; pinned link keeps attachment alive */
    } else {
        fprintf(stderr, "Attached. Press Enter to detach...\n");
        getchar();
        // link will detach on process exit when link is destroyed
    }

    bpf_link__destroy(link);
    bpf_object__close(ext_obj);
    if (target_obj)
        bpf_object__close(target_obj);
    if (target_prog_fd >= 0 && target_id >= 0)
        close(target_prog_fd);

    return 0;
}
