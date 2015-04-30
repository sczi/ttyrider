#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

/* target pid and fd to monitor */
pid_t pid;
int fd;
/* saved tty settings */
struct termios prev;
/* shared flag to say whether ptrace should hide writes in target process */
pthread_mutex_t hidden_lock = PTHREAD_MUTEX_INITIALIZER;
int hidden_flag = 0;

void set_hidden()
{
    pthread_mutex_lock(&hidden_lock);
    hidden_flag = 1;
    pthread_mutex_unlock(&hidden_lock);
}

void unset_hidden()
{
    pthread_mutex_lock(&hidden_lock);
    hidden_flag = 0;
    pthread_mutex_unlock(&hidden_lock);
}

int is_hidden()
{
    pthread_mutex_lock(&hidden_lock);
    int ret = hidden_flag;
    pthread_mutex_unlock(&hidden_lock);
    return ret;
}

/* sigterm handler */
void term(int signum)
{
    /* restore original tty settings */
    tcsetattr(STDIN_FILENO, TCSANOW, &prev);
    printf("\n");
    exit(0);
}

/* from The Linux Programming Interface */
/* Place terminal referred to by 'fd' in raw mode (noncanonical mode
   with all input and output processing disabled). Return 0 on success,
   or -1 on error. If 'prevTermios' is non-NULL, then use the buffer to
   which it points to return the previous terminal settings. */

int ttySetRaw(int fd, struct termios *prevTermios)
{
    struct termios t;

    if (tcgetattr(fd, &t) == -1)
        return -1;

    if (prevTermios != NULL)
        *prevTermios = t;

    t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO);
                        /* Noncanonical mode, disable signals, extended
                           input processing, and echoing */

    t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR |
                      INPCK | ISTRIP | IXON | PARMRK);
                        /* Disable special handling of CR, NL, and BREAK.
                           No 8th-bit stripping or parity error handling.
                           Disable START/STOP output flow control. */

    t.c_oflag &= ~OPOST;                /* Disable all output processing */

    t.c_cc[VMIN] = 1;                   /* Character-at-a-time input */
    t.c_cc[VTIME] = 0;                  /* with blocking */

    if (tcsetattr(fd, TCSAFLUSH, &t) == -1)
        return -1;

    return 0;
}

/* display out that pid sends to fd */
void* mirror_output(void *unused)
{
    int status;

    ptrace(PTRACE_ATTACH, pid, 0, 0);
    wait(0);

    while(1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        if(WIFEXITED(status))
            break;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        /* ssize_t write(int fd, const void *buf, size_t count)
         * fd:   regs.rdi
         * buf:  regs.rsi
         * size: regs.rdx
         */
        if(regs.orig_rax == SYS_write && regs.rdi == fd) {
            int i;
            char *buf = malloc(regs.rdx + sizeof(long));

            for(i = 0; i < regs.rdx; i += sizeof(long)) {
                long val = ptrace(PTRACE_PEEKDATA, pid, regs.rsi + i, 0);
                memcpy(buf + i, &val, sizeof(long));
            }

            write(1, buf, regs.rdx);
            free(buf);

            /* discard writes if hidden_flag is set */
            if(is_hidden()) {
                memset(buf, 0, regs.rdx);
                for(i = 0; i < regs.rdx; i += sizeof(long))
                    ptrace(PTRACE_POKEDATA, pid, regs.rsi + i, *(long *)(buf + i));
            }
        }
        // don't care about return value of syscall
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        if(WIFEXITED(status))
            break;
    }

    raise(SIGTERM);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t output_thread;
    int status;
    ttySetRaw(STDIN_FILENO, &prev);

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);

    pid = atoi(argv[1]);
    fd = atoi(argv[2]);
    /* mirror output in another thread */
    status = pthread_create(&output_thread, NULL, mirror_output, NULL);

    /* in parent go on to send them our input */
    char devname[80];
    snprintf(devname, sizeof(devname), "/proc/%d/fd/0", pid);
    int fd = open(devname, O_WRONLY);
    while(1) {
        char c = getchar();

        /* ctrl-A */
        if(c == 0x01) {
            c = getchar();
            if (c == 'd')
                break;
            else if (c == 's')
                set_hidden();
            else if (c == 'q')
                unset_hidden();
            /* for 2x ctrl-A send a real ctrl-A */
            else if (c == 0x01)
                ioctl(fd, TIOCSTI, &c);
        } else
            ioctl(fd, TIOCSTI, &c);
    }

    /* wait on ptrace-ing thread to finish */
    pthread_cancel(output_thread);
    pthread_join(output_thread, NULL);

    /* restore original tty settings */
    tcsetattr(STDIN_FILENO, TCSANOW, &prev);
    printf("\n");
    return 0;
}
