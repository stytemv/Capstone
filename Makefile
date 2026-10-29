# ============================================================
# Makefile 설명
# ============================================================
#
# 1. 빌드 구조
#
# 이 Makefile은 eBPF 프로그램과 사용자 공간 프로그램의 컴파일 및 링크 과정을 위한 Makefile.
#
# 전체 빌드 과정:
#
#   memwatch.bpf.c
#       |
#       v
#   memwatch.bpf.o       (Clang으로 eBPF 오브젝트 생성)
#       |
#       v
#   memwatch.skel.h      (bpftool로 Skeleton 생성)
#       |
#       v
#   memwatch.c
#       |
#       v
#   memwatch.o           (GCC로 사용자 공간 코드 컴파일)
#       |
#       v
#   memwatch             (오브젝트 파일 링크)
#
#
# 2. 변수 설명
#
# CC:
#   사용자 공간 C 프로그램을 컴파일할 컴파일러.
#
# CLANG:
#   eBPF 바이트코드를 생성할 컴파일러.
#
# BPFTOOL:
#   eBPF 오브젝트로부터 Skeleton 헤더를 생성하는 도구.
#
# TARGET:
#   최종적으로 생성할 실행 파일의 이름.
#
# USER_SRCS:
#   사용자 공간 C 소스 파일 목록.
#   기능을 분리하여 새로운 .c 파일을 추가할 때 수정한다.
#
# BPF_SRCS:
#   eBPF C 소스 파일 목록.
#
# USER_OBJS:
#   USER_SRCS에 대응하는 사용자 공간 오브젝트 파일 목록.
#
# BPF_OBJS:
#   BPF_SRCS에 대응하는 eBPF 오브젝트 파일 목록.
#
# BPF_SKELS:
#   eBPF 오브젝트에서 생성할 Skeleton 헤더 파일 목록.
#
# USER_DEPS:
#   GCC가 생성하는 헤더 의존성 정보(.d) 파일 목록.
#
#
# 3. 컴파일 옵션
#
# -g:
#   디버깅 정보를 생성한다.
#
# -O2:
#   컴파일러 최적화를 활성화한다.
#
# -Wall -Wextra:
#   일반적인 경고와 추가 경고를 활성화한다.
#
# -MMD -MP:
#   사용자 공간 소스의 헤더 의존성 정보를 생성한다.
#   헤더가 변경되면 관련 오브젝트를 다시 컴파일한다.
#
# -target bpf:
#   eBPF를 대상으로 컴파일하도록 지정한다.
#
# -D__TARGET_ARCH_x86:
#   BPF 프로그램의 대상 아키텍처를 x86으로 지정한다.
#
# -I.:
#   현재 디렉터리를 헤더 파일 검색 경로에 추가한다.
#
# -lbpf -lelf -lz:
#   libbpf, libelf, zlib 라이브러리를 링크한다.
#
#
# 4. 빌드 규칙
#
# all:
#   기본 빌드 대상이며 memwatch 실행 파일을 생성한다.
#
# %.bpf.o:
#   .bpf.c 소스 파일을 eBPF 오브젝트 파일로 컴파일한다.
#
# %.skel.h:
#   eBPF 오브젝트 파일에서 Skeleton 헤더를 생성한다.
#
# %.o:
#   사용자 공간 C 소스 파일을 오브젝트 파일로 컴파일한다.
#
# $(TARGET):
#   사용자 공간 오브젝트 파일들을 링크하여
#   최종 실행 파일을 생성한다.
#
# victim.out:
#   테스트용 victim.c를 별도로 컴파일한다.
#
# rebuild:
#   기존 빌드 결과를 제거하고 기본 대상을 다시 빌드한다.
#
# clean:
#   실행 파일, 오브젝트 파일, Skeleton 헤더,
#   의존성 파일 등 생성된 빌드 결과를 삭제한다.
#
#
# 5. 의존성 관리
#
# Make는 대상 파일과 의존 파일의 수정 시간을 비교한다.
# 의존 파일이 더 최신이면 해당 대상을 다시 빌드한다.
#
# 예시:
#
#   memwatch.bpf.c 수정
#       |
#       v
#   memwatch.bpf.o 재컴파일
#       |
#       v
#   memwatch.skel.h 재생성
#       |
#       v
#   memwatch.o 재컴파일
#       |
#       v
#   memwatch 실행 파일 재링크
#
# GCC는 -MMD -MP 옵션을 통해 .d 파일을 생성한다.
# -include 지시문은 생성된 의존성 파일을 읽어 들인다.
#
# 따라서 사용자 공간 코드에서 참조하는 헤더가 변경되면
# 해당 헤더에 의존하는 오브젝트 파일을 다시 컴파일한다.
#
# 단, eBPF 소스의 헤더 의존성은 현재 수동으로 지정한다.
#
#
# 6. 사용 방법
#
# make
#   변경된 파일을 확인하고 필요한 부분만 빌드한다.
#
# make rebuild
#   기존 빌드 결과를 삭제하고 memwatch를 다시 빌드한다.
#
# make clean
#   생성된 빌드 파일을 삭제한다.
#
# make victim.out
#   테스트용 victim 프로그램을 빌드한다.
#
#
# 7. 프로젝트 확장
#
# 사용자 공간 소스 파일을 추가하는 경우:
#
#   USER_SRCS := memwatch.c event.c filter.c
#
# eBPF 소스 파일을 추가하는 경우:
#
#   BPF_SRCS := memwatch.bpf.c trace.bpf.c
#
# 사용자 공간 소스는 각각 오브젝트 파일로 컴파일된 후
# 최종 실행 파일로 링크된다.
#
# eBPF 소스는 각각 독립적인 오브젝트 파일과
# Skeleton 헤더를 생성할 수 있다.
#
# 단, 새로운 eBPF 프로그램을 추가하면 해당 Skeleton을
# 사용하는 사용자 공간 코드도 함께 구현해야 한다.
#
# 현재 Makefile은 소규모 libbpf 프로젝트를 기준으로 하며,
# 프로그램 구조가 복잡해지면 빌드 규칙을 확장할 수 있다.
#
# ============================================================

CC := gcc
CLANG := clang
BPFTOOL := bpftool

TARGETS := memwatch victim.out

# Source files
USER_SRCS := memwatch.c
BPF_SRCS := memwatch.bpf.c

# Generated files
USER_OBJS := $(USER_SRCS:.c=.o)
BPF_OBJS := $(BPF_SRCS:.c=.o)
BPF_SKELS := $(BPF_SRCS:.bpf.c=.skel.h)
USER_DEPS := $(USER_OBJS:.o=.d)

# Compiler options
CFLAGS := -g -O2 -Wall -Wextra -MMD -MP
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.
LDLIBS := -lbpf -lelf -lz

.PHONY: all clean rebuild

all: $(TARGETS)

# Compile eBPF programs
%.bpf.o: %.bpf.c memwatch.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton headers
%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Userspace objects depend on skeleton headers
$(USER_OBJS): $(BPF_SKELS)

# Compile userspace programs
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
memwatch: $(USER_OBJS)
	$(CC) $(USER_OBJS) -o $@ $(LDLIBS)

# Test victim
victim.out: victim.c
	$(CC) $(CFLAGS) $< -o $@

# Full rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all

# Remove generated files
clean:
	rm -f $(TARGETS) $(USER_OBJS) $(USER_DEPS) \
	      $(BPF_OBJS) $(BPF_SKELS)

-include $(USER_DEPS)

