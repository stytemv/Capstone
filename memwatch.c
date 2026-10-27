
#include <stdio.h>
#include <stdlib.h>             // strtol()
#include <limits.h>             // INT_MAX
#include <errno.h>              // errno, EINTR
#include <signal.h>             // signal(), kill()
#include <unistd.h>             // pipe(), fork(), read(), write(), execvp()
#include <sys/types.h>          // pid_t
#include <sys/wait.h>           // waitpid()
#include <linux/types.h>        // __u32, __u64
#include <bpf/bpf.h>            // bpf_map_update_elem()
#include <bpf/libbpf.h>         // libbpf 및 Ring Buffer API

#include "memwatch.h"           // Kernel/User-space 공통 이벤트 구조체
#include "memwatch.skel.h"      // 자동 생성된 BPF Skeleton

static volatile sig_atomic_t exiting = 0;


/*
 * Signal Handler
 * SIGINT(Ctrl-C), SIGTERM 발생 시 종료 플래그 설정
 */
static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}


/*
 * Ring Buffer Callback
 * Kernel에서 전달된 이벤트를 공통 구조체로 해석하여 출력
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    const struct mem_event *e = data;

    if (data_sz < sizeof(*e))
        return 0;

    if (e->type == MEM_EVENT_MMAP) {
        printf("[MMAP] TIME=%llu PID=%u TID=%u COMM=%s\n",
               (unsigned long long)e->timestamp_ns,
               e->pid,
               e->tid,
               e->comm);
    }

    return 0;
}


int main(int argc, char **argv)
{
    struct memwatch_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    __u32 target_pid = 0;
    __u32 key = 0;

    pid_t child_pid = -1;
    int pipefd[2] = {-1, -1};
    int child_status = 0;
    int child_reaped = 0;

    char *endptr;
    long parsed_pid;
    int pid_mode;
    int err = 0;


    /*
     * Argument Parsing
     * 숫자 인자라면 기존 PID 감시 모드
     * 그 외에는 실행 파일 경로로 처리
     */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID | PROGRAM> [ARGS...]\n", argv[0]);
        return 1;
    }

    errno = 0;
    parsed_pid = strtol(argv[1], &endptr, 10);

    pid_mode = (endptr != argv[1] && *endptr == '\0');

    if (pid_mode) {
        if (argc != 2 || errno != 0 ||
            parsed_pid <= 0 || parsed_pid > INT_MAX) {
            fprintf(stderr, "Invalid PID or arguments\n");
            return 1;
        }

        target_pid = (__u32)parsed_pid;
    } else if (argv[1][0] == '-') {
        fprintf(stderr, "Invalid program path: %s\n", argv[1]);
        return 1;
    }


    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);    // Pipe 수신자가 종료되어도 부모가 강제 종료되지 않도록 설정


    /*
     * Step 1: Open
     * BPF Object를 User-space에서 열고 초기화
     */
    skel = memwatch_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }


    /*
     * Step 2: Load
     * BPF Program과 Map을 Kernel에 Load
     */
    err = memwatch_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }


    /*
     * Target Program Launcher
     * 프로그램 실행 모드인 경우 Pipe와 자식 프로세스 생성
     */
    if (!pid_mode) {

        /*
         * Pipe 생성
         * 부모의 감시 준비가 완료될 때까지 자식 실행을 대기시키는 용도
         *
         * pipefd[0]: Read
         * pipefd[1]: Write
         */
        if (pipe(pipefd) == -1) {
            perror("pipe");
            err = -1;
            goto cleanup;
        }


        /*
         * Fork
         * 자식 프로세스를 생성하고 반환값으로 부모/자식 구분
         */
        child_pid = fork();

        if (child_pid < 0) {
            perror("fork");
            err = -1;
            goto cleanup;
        }

        if (child_pid == 0) {
            /*
             * Child Process
             * 부모가 Pipe에 신호를 보낼 때까지 대기
             */
            char start_signal;
            ssize_t n;

            close(pipefd[1]);   // 자식은 Read만 사용

            // 부모의 Signal Handler를 상속하지 않도록 기본 동작 복원
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            signal(SIGPIPE, SIG_DFL);

            do {
                n = read(pipefd[0], &start_signal, 1);
            } while (n < 0 && errno == EINTR);

            close(pipefd[0]);

            if (n != 1 || start_signal != 'S')
                _exit(1);

            /*
             * Exec
             * 자식 프로세스를 대상 프로그램으로 교체
             * PID는 유지되며 argv[1] 이후 인자도 전달
             */
            execvp(argv[1], &argv[1]);

            // execvp() 성공 시 아래 코드는 실행되지 않음
            perror("execvp");
            _exit(127);
        }

        /*
         * Parent Process
         * fork()가 반환한 자식 PID를 감시 대상으로 설정
         */
        close(pipefd[0]);
        pipefd[0] = -1;

        target_pid = (__u32)child_pid;
    }


    /*
     * Set Target PID
     * BPF ARRAY Map의 Key 0에 감시 대상 PID 저장
     */
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.target_pid_map),
        &key,
        &target_pid,
        BPF_ANY
    );

    if (err) {
        perror("Failed to update target PID map");
        goto cleanup;
    }


    /*
     * Step 3: Attach
     * 감시 대상 PID 설정 후 BPF Program을 Tracepoint에 연결
     */
    err = memwatch_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }


    /*
     * Ring Buffer Consumer 생성
     * events Map과 Callback 연결
     */
    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create Ring Buffer\n");
        err = -1;
        goto cleanup;
    }


    printf("memwatch started. Target PID: %u\n", target_pid);
    printf("Press Ctrl-C to exit.\n");
    fflush(stdout);


    /*
     * Release Child
     * Attach 및 Ring Buffer 준비가 완료된 후
     * Pipe에 신호를 보내 자식의 execvp() 실행을 허용
     */
    if (!pid_mode) {
        char start_signal = 'S';
        ssize_t n;

        if (exiting) {
            err = -EINTR;
            goto cleanup;
        }

        do {
            n = write(pipefd[1], &start_signal, 1);
        } while (n < 0 && errno == EINTR);

        if (n != 1) {
            perror("Failed to release child");
            err = -1;
            goto cleanup;
        }

        close(pipefd[1]);
        pipefd[1] = -1;
    }


    /*
     * Ring Buffer Polling
     * 이벤트 수신 시 Callback 실행
     * Launcher 모드에서는 자식 프로세스의 종료 여부도 확인
     */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            err = 0;
            continue;
        }

        if (err < 0) {
            fprintf(stderr, "Ring Buffer polling failed: %d\n", err);
            break;
        }

        if (!pid_mode) {
            /*
             * waitpid(WNOHANG)
             * 자식의 종료 여부를 확인하되 부모 프로세스는 대기하지 않음
             */
            pid_t result = waitpid(child_pid, &child_status, WNOHANG);

            if (result == child_pid) {
                child_reaped = 1;

                // 자식 종료 직전 발생한 잔여 이벤트 처리
                int remaining = ring_buffer__poll(rb, 0);
                if (remaining < 0 && remaining != -EINTR)
                    err = remaining;
                else
                    err = 0;

                printf("Target process %d exited.\n", child_pid);
                break;
            }

            if (result < 0 && errno != EINTR) {
                perror("waitpid");
                err = -1;
                break;
            }
        }
    }


cleanup:
    /*
     * Step 4: Destroy
     * Pipe, 자식 프로세스, Ring Buffer, Skeleton Resource 정리
     */

    if (pipefd[0] >= 0)
        close(pipefd[0]);

    if (pipefd[1] >= 0)
        close(pipefd[1]);

    /*
     * Launcher 모드에서 자식이 아직 실행 중이라면 종료 요청
     * 자식이 이미 회수된 경우에는 실행하지 않음
     */
    if (child_pid > 0 && !child_reaped) {
        kill(child_pid, SIGTERM);

        while (waitpid(child_pid, &child_status, 0) < 0 &&
               errno == EINTR) {
        }
    }

    ring_buffer__free(rb);
    memwatch_bpf__destroy(skel);

    return err < 0 ? 1 : 0;
}

