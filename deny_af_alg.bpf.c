// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_ALG 38
#define EPERM 1

struct event {
    u32  pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer
} events SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(deny_af_alg_create, int family, int type, int protocol, int kern, int ret)
{
    /* ret is the return value from the previous BPF program
    * or 0 if it's the first hook.
    */
    if (ret != 0)
        return ret;

    if (family != AF_ALG)
        return 0;
    // Allocate space in the ring buffer
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    // Buffer full
    if (!e)
        return -EPERM;
    // Fill the data
    e->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // Push it to userspace
    bpf_ringbuf_submit(e, 0);

    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
