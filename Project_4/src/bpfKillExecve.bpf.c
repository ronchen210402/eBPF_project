// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// boris: Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


const volatile int target_ppid = 0;

SEC("tp/syscalls/sys_enter_execve") //boris: since our goal is to kill execve syscall!
int bpf_KillExecve(struct trace_event_raw_sys_enter *ctx)
{
    long ret = 0;
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;//boris:take upper 32 bits as pid.


    
    //boris: if bpf_send_signal successfully sends the desired signal, it will return 0,  
    //which means ret will get 0; 9 == SIGKILL
    ret = bpf_send_signal(9);
    
    
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0); //boris: ret == 0 means successfully sent SIGKILL.
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
