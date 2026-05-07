#include "deny_af_alg.skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

struct event {
    __u32 pid;
    char  comm[16];
};

static volatile int running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct event)) {
        fprintf(stderr, "warn: short event (%zu bytes)\n", size);
        return 0;
    }

    const struct event *e = data;
    fprintf(stderr, "BLOCKED pid=%-6u comm=%-16s\n",
           e->pid, e->comm);
    return 0;

}

int main(void)
{
    struct deny_af_alg_bpf *skel = NULL;
    struct ring_buffer      *rb  = NULL;
    int err;

    /* Silence libbpf debug noise; bump to LIBBPF_DEBUG if needed */
    libbpf_set_print(NULL);

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* Load & verify BPF program */
    skel = deny_af_alg_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load skeleton: %s\n", strerror(errno));
        return 1;
    }

    /* Attach LSM hook */
    err = deny_af_alg_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF program: %s\n", strerror(-err));
        goto cleanup;
    }

    /* Set up ring buffer consumer */
    rb = ring_buffer__new(
            bpf_map__fd(skel->maps.events),
            handle_event,
            NULL,   /* ctx */
            NULL    /* opts */
    );
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    printf("Listening for AF_ALG socket create attempts... (Ctrl-C to stop)\n");

    while (running) {
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    deny_af_alg_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
