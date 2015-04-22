#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

void mirror_output(pid_t pid, int fd) {
    ptrace(PTRACE_ATTACH, pid, 0, 0);
    wait(0);

    while(1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(0);
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        /* ssize_t write(int fd, const void *buf, size_t count)
         * fd:   regs.rdi
         * buf:  regs.rsi
         * size: regs.rdx
         */
        if(regs.orig_rax == SYS_write && regs.rdi == fd) {
            int i;
            char *buf = malloc(regs.rdx);

            for(i = 0; i < regs.rdx; i += sizeof(long)) {
                long val = ptrace(PTRACE_PEEKDATA, pid, regs.rsi + i, 0);
                memcpy(buf + i, &val, MIN(sizeof(long), regs.rdx - i));
            }

            write(1, buf, regs.rdx);
            free(buf);
        }
        // don't check return value 
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(0);
    }
}

int main(int argc, char **argv) {
    /* mirror output in child */
    if(fork() == 0)
        mirror_output(atoi(argv[1]), atoi(argv[2]));

    /* in parent go on to send them our input */
    char devname[80];
    snprintf(devname, sizeof(devname), "/proc/%s/fd/0", argv[1]);
    int fd = open(devname, O_WRONLY);
    while(1) {
        char c = getchar();
        ioctl(fd, TIOCSTI, &c);
    }

    /* wait on ptrace-ing child to finish */
    wait(0);
}
