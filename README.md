# deny-af-alg-bpf

## Description

BPF LSM program that blocks `AF_ALG` (Linux kernel crypto API) socket creation and logs all attempts via a ring buffer to userspace.

### What it does

- Attaches to the `lsm/socket_create` hook
- Denies any `socket(AF_ALG, ...)` call with `-EPERM`
- Emits structured events (pid, comm) to a BPF ring buffer
- Userspace daemon reads the ring buffer and logs to stderr (consumed by systemd journal)

### Components

Programs

- `deny_af_alg.bpf.c` - main block logic, work in bpf (kernel space)
- `deny_af_alg.user.c` - userspace program
  - load bpf program
  - connect to exposed ring buffer
  - get info about denied access and log to stdout

Systemd

- `deny-af-alg.service` - main service, contains userspace app and bpf program
- `deny-af-alg-bpf.service` - legacy service, works via bpftool, dont contains logging

### CVE Fix Information

This eBPF program addresses **CVE-2026-31431**. It resolves the vulnerability by restricted access to crypto socket

### Requirements

Need bfp in lsm

```bash
#cat /sys/kernel/security/lsm
lockdown,capability,yama,selinux,bpf
```

### Build

> **Note on `vmlinux.h`:** `vmlinux.h` generated on build machine.

> If you are targeting a different kernel, regenerate it on the target machine before building:
> ```bash
> bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
> ```

Build via makefile

```bash
make
```

Build artifacts are placed in the project root:
 
| File | Description |
|------|-------------|
| `deny_af_alg` | Userspace daemon |
| `deny_af_alg.bpf.o` | Compiled BPF object |
| `deny_af_alg.skel.h` | Generated BPF skeleton header |
| `vmlinux.h` | Generated linux headers via btf |

### Run via command line

```bash
sudo ./deny_af_alg
```

output

```
Listening for AF_ALG socket create attempts... (Ctrl-C to stop)
BLOCKED pid=12345  comm=python3
```

### Run via systemd

Copy `deny-af-alg.service` file and binary to target machine.

Run via systemd

```bash
systemctl start deny-af-alg.service
```

### Run only bpf prog manual via bpftool

```bash
bpftool prog loadall deny_af_alg.bpf.o /sys/fs/bpf/deny_af_alg autoattach
```

### Additional command

Preparation

```bash
dnf install -y bpftool libbpf-devel clang llvm kernel-devel
```

Compile

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -c deny_af_alg.bpf.c -o deny_af_alg.bpf.o
```

Check

```bash
bpftool prog list | grep deny_af_alg
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
