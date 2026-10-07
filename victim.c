#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void)
{
    pid_t pid = getpid();

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        perror("sysconf");
        return 1;
    }

    printf("PID: %d\n", pid);
    printf("Page size: %ld bytes\n\n", page_size);

    /*
     * Step 1
     * Anonymous memory mapping:
     *   permission = Read + Write
     */
    void *addr = mmap(
        NULL,
        page_size,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[1] mmap()\n");
    printf("    address : %p\n", addr);
    printf("    size    : %ld\n", page_size);
    printf("    perm    : RW-\n");
    printf("\nPress Enter to call mprotect()...\n");
    getchar();


    /*
     * Step 2
     * Change permission:
     *   Read + Write
     *       ->
     *   Read + Execute
     */
    if (mprotect(addr, page_size, PROT_READ | PROT_EXEC) == -1) {
        perror("mprotect");
        munmap(addr, page_size);
        return 1;
    }

    printf("\n[2] mprotect()\n");
    printf("    address : %p\n", addr);
    printf("    size    : %ld\n", page_size);
    printf("    perm    : RW- -> R-X\n");
    printf("\nPress Enter to call munmap()...\n");
    getchar();


    /*
     * Step 3
     * Remove the mapping.
     */
    if (munmap(addr, page_size) == -1) {
        perror("munmap");
        return 1;
    }

    printf("\n[3] munmap()\n");
    printf("    address : %p\n", addr);
    printf("    mapping removed\n");

    return 0;
}
