#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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

/* target pid and fd to monitor */
pid_t pid;
int read_fd, write_fd, target_tty_fd;
/* saved tty settings */
struct termios prev;
/* shared flag to say whether ptrace should hide writes in target process */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
/* should output be hidden */
int hidden_flag = 0;
/* hide the next counter input characters */
int hide_counter = 0;
int auto_hide = 1;
FILE *debug_log;

void reset_tty_and_exit(int status)
{
    /* restore original tty settings */
    tcsetattr(STDIN_FILENO, TCSANOW, &prev);
    printf("\n");
    exit(status);
}

void die(const char* format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);
    reset_tty_and_exit(1);
}

void set_hidden()
{
    pthread_mutex_lock(&lock);
    hidden_flag = 1;
    pthread_mutex_unlock(&lock);
}

void unset_hidden()
{
    pthread_mutex_lock(&lock);
    hidden_flag = 0;
    pthread_mutex_unlock(&lock);
}

int is_hidden()
{
    pthread_mutex_lock(&lock);
    int ret = hidden_flag;
    pthread_mutex_unlock(&lock);
    return ret;
}

int is_hide_counter_zero()
{
    pthread_mutex_lock(&lock);
    int ret = (hide_counter == 0);
    pthread_mutex_unlock(&lock);
    return ret;
}

void subtract_hide_counter(int dec)
{
    pthread_mutex_lock(&lock);
    hide_counter -= dec;
    if(hide_counter < 0)
        hide_counter = 0;
    pthread_mutex_unlock(&lock);
}

void increment_hide_counter()
{
    pthread_mutex_lock(&lock);
    hide_counter++;
    pthread_mutex_unlock(&lock);
}

void check_window_size()
{
    struct winsize ws_ours, ws_target;
    ioctl(0, TIOCGWINSZ, &ws_ours);
    ioctl(target_tty_fd, TIOCGWINSZ, &ws_target);
    if (ws_ours.ws_row < ws_target.ws_row || ws_ours.ws_col < ws_target.ws_col)
        die("current tty is smaller than the tty you want to hijack: %dx%d vs %dx%d\n",
                ws_ours.ws_row, ws_ours.ws_col, ws_target.ws_row, ws_target.ws_col);
}

/* sigterm handler */
void term(int signum)
{
    reset_tty_and_exit(0);
}

/* make sure our tty is still large enough for the one we're hijacking */
static void sigwinchHandler(int sig)
{
    check_window_size();
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

/* display output that pid sends to fd */
void* mirror_output(void *unused)
{
    int status;

    ptrace(PTRACE_ATTACH, pid, 0, 0);
    wait(0);

    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        if (WIFEXITED(status))
            break;

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        /* ssize_t write(int fd, const void *buf, size_t count)
         * fd:   regs.rdi
         * buf:  regs.rsi
         * size: regs.rdx
         */
        if (regs.orig_rax == SYS_write && (regs.rdi == write_fd || regs.rdi == 1)) {
            int i;
            char *buf = malloc(regs.rdx + sizeof(long));

            for (i = 0; i < regs.rdx; i += sizeof(long)) {
                long val = ptrace(PTRACE_PEEKDATA, pid, regs.rsi + i, 0);
                memcpy(buf + i, &val, sizeof(long));
            }

            write(1, buf, regs.rdx);
            /* fprintf(debug_log, "sending output:\n"); */
            /* fflush(debug_log); */
            /* write(fileno(debug_log), buf, regs.rdx); */
            free(buf);

            /* discard writes if hidden_flag is set */
            if (is_hidden()) {
                memset(buf, 0, regs.rdx);
                for (i = 0; i < regs.rdx; i += sizeof(long))
                    ptrace(PTRACE_POKEDATA, pid, regs.rsi + i, *(long *)(buf + i));
            }
        }

        /* return of the syscall */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        if (WIFEXITED(status))
            break;
        if (regs.orig_rax == SYS_read && (regs.rdi == read_fd || regs.rdi == 0)) {
            if (is_hide_counter_zero())
                unset_hidden();

            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            if (regs.rax >= 0)
                subtract_hide_counter(regs.rax);
        }
    }

    raise(SIGTERM);
    return NULL;
}

int main(int argc, char **argv)
{
    /* debug_log = fopen("ttyrider.log", "w"); */
    pthread_t output_thread;
    int status;
    ttySetRaw(STDIN_FILENO, &prev);

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigwinchHandler;
    sigaction(SIGWINCH, &action, NULL);

    pid = atoi(argv[1]);
    read_fd = atoi(argv[2]);
    write_fd = atoi(argv[3]);
    /* mirror output in another thread */
    status = pthread_create(&output_thread, NULL, mirror_output, NULL);

    /* in parent go on to send them our input */
    char devname[80];
    snprintf(devname, sizeof(devname), "/proc/%d/fd/0", pid);
    target_tty_fd = open(devname, O_WRONLY);
    /* check that our terminal is large enough for the display we're mirroring */
    check_window_size();

    int c;
    /* send a refresh at the start */
    c = 0x0c;
    set_hidden();
    increment_hide_counter();
    ioctl(target_tty_fd, TIOCSTI, &c);
    while (1) {
        c = getchar();
        if (c == EOF)
            continue;
        /* fprintf(debug_log, "got char: %0x\n", c); */
        /* fflush(debug_log); */

        /* ctrl-A */
        if (c == 0x01) {
            c = getchar();
            if (c == 'd')
                break;
            else if (c == 's')
                set_hidden();
            else if (c == 'q')
                unset_hidden();
            else if (c == 'h')
                auto_hide = !auto_hide;
            /* for 2x ctrl-A send a real ctrl-A */
            else if (c == 0x01) {
                if (auto_hide) {
                    set_hidden();
                    increment_hide_counter();
                }
                ioctl(target_tty_fd, TIOCSTI, &c);
            }
        } else {
            if (auto_hide) {
                set_hidden();
                increment_hide_counter();
            }
            ioctl(target_tty_fd, TIOCSTI, &c);
        }
    }

    /* wait on ptrace-ing thread to finish */
    pthread_cancel(output_thread);
    pthread_join(output_thread, NULL);

    reset_tty_and_exit(0);
}
