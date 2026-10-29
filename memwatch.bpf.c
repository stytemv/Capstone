#include "vmlinux.h"
#include "memwatch.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";


/*
 * Ring Buffer Map
 * eBPF에서 생성한 이벤트를 User-space로 전달
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");


/*
 * Target PID Map
 * User-space에서 전달한 감시 대상 PID를 저장
 *
 * ARRAY Map:
 *   key   = 0
 *   value = 감시할 PID
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();  // 상위 32bit: TGID(PID), 하위 32bit: TID
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;


    /*
     * PID Filtering
     * BPF Map에서 감시 대상 PID를 읽고 현재 PID와 비교
     */
    __u32 key = 0;
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);

    if (!target_pid || *target_pid == 0 || pid != *target_pid)
        return 0;


    /*
     * Ring Buffer Reserve
     * 이벤트 구조체 하나를 저장할 공간 확보
     */
    struct mem_event *e = bpf_ringbuf_reserve(
        &events,
        sizeof(struct mem_event),
        0
    );

    if (!e)
        return 0;


    /* Event 데이터 작성 */
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->type = MEM_EVENT_MMAP;
    e->reserved = 0;


    bpf_get_current_comm(e->comm, sizeof(e->comm));  // 현재 실행 이름을 가져옴


    /*
    * mmap() Arguments 추출
    *
    ctx는 sys_enter_mmap Tracepoint가 전달한 Context.
    *
    * trace_event_raw_sys_enter의 args 배열에는
    * syscall 호출 시 전달된 인자들이 순서대로 저장되어 있다.
    *
    * mmap() Prototype:
    *
    * void *mmap(void *addr, size_t length,
    *            int prot, int flags,
    *            int fd, off_t offset);
    *
    * args[0] = addr
    * args[1] = length
    * args[2] = prot
    * args[3] = flags
    * args[4] = fd
    * args[5] = offset
    *
    * 주의:
    * sys_enter_mmap에서는 요청 인자만 확인 가능하다.
    * addr은 실제 할당된 주소가 아니라 요청한 주소다.
    */
    e->addr   = ctx->args[0];
    e->length = ctx->args[1];
    e->prot   = ctx->args[2];
    e->flags  = ctx->args[3];
    e->fd     = (__s32)ctx->args[4];
    e->offset = ctx->args[5];




    /* 작성한 이벤트를 Ring Buffer에 제출 */
    bpf_ringbuf_submit(e, 0);

    return 0;
}
