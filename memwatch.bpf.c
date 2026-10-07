#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();	// 현재 프로세스의 TGID와 TID를 64-bit 값으로 반환
    						// 상위 32bit: TGID(PID), 하위 32bit: TID
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm)); 	// 현재 프로세스의 실행 이름(comm)을 가져옴

    bpf_printk("PID=%u TID=%u COMM=%s", pid, tid, comm);

    return 0;
}
