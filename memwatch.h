#ifndef MEMWATCH_H
#define MEMWATCH_H

/*
 * Event Type
 * 발생한 메모리 관련 이벤트의 종류를 구분
 * 추후 mprotect, munmap 등 추가 예정
 */
enum mem_event_type {
    MEM_EVENT_MMAP = 1,
};


/*
 * Memory Event
 * eBPF에서 생성하여 Ring Buffer를 통해
 * User-space로 전달할 공통 데이터 구조체
 *
 * __u32, __u64는 이 헤더를 포함하기 전에 정의되어 있어야 함
 */
struct mem_event {
    __u64 timestamp_ns;     // 이벤트 발생 시각 (커널 단조 시계 기준, ns)

    __u32 pid;              // 프로세스 ID (TGID)
    __u32 tid;              // 스레드 ID (TID)
    __u32 type;             // 이벤트 종류 (mem_event_type)
    __u32 reserved;         // 구조체 정렬을 위한 예약 영역

    char comm[16];          // 프로세스 실행 이름 (TASK_COMM_LEN)
};

#endif
