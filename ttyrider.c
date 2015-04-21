#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

int main(int argc, char **argv) {
    pid_t target_pid = atoi(argv[1]);
    int target_fd = atoi(argv[2]);

    ptrace(PTRACE_ATTACH, target_pid, 0, 0);
    wait(0);

    while(1) {
        ptrace(PTRACE_SYSCALL, target_pid, 0, 0);
        wait(0);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, target_pid, 0, &regs);
        /* ssize_t write(int fd, const void *buf, size_t count)
         * fd:   regs.rdi
         * buf:  regs.rsi
         * size: regs.rdx
         */
        if(regs.orig_rax == SYS_write && regs.rdi == target_fd) {
            int i;
            char *buf = malloc(regs.rdx);

            for(i = 0; i < regs.rdx; i += sizeof(long)) {
                long val = ptrace(PTRACE_PEEKDATA, target_pid, regs.rsi + i, 0);
                memcpy(buf + i, &val, MIN(sizeof(long), regs.rdx - i));
            }

            write(1, buf, regs.rdx);
            free(buf);
        }
        // don't check return value 
        ptrace(PTRACE_SYSCALL, target_pid, 0, 0);
        wait(0);
    }
}
