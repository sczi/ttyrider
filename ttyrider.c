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
#include <getopt.h>

/* target pid and fd to monitor */
pid_t pid;
int read_fd=0, write_fd=1, target_tty_fd, have_root;
/* saved tty settings */
struct termios prev;
/* shared flag to say whether ptrace should hide writes in target process */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
/* for sending chars for the ptrace thread to inject */
char forced_input_char = 1;
pthread_cond_t input_ready;
/* should output be hidden */
int hidden_flag = 0;
/* hide the next counter input characters */
int hide_counter = 0;
int auto_hide = 1;
int send_clear = 1;

/* for 32-bit vs 64-bit ptrace code */
#if defined __x86_64__
#   define ORIG_AX orig_rax
#   define ARG1 rdi
#   define ARG2 rsi
#   define ARG3 rdx
#   define SP rsp
#   define AX rax
#   define IP rip
#else
#   define ORIG_AX orig_eax
#   define ARG1 ebx
#   define ARG2 ecx
#   define ARG3 edx
#   define SP esp
#   define AX eax
#   define IP eip
#endif

void usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "   ttyrider -p pid [-h] [-l 0 or 1] [-a 0 or 1] [-r input_fd] [-w output_fd]\n"
            "       -p pid:         pid of the target\n"
            "       -h:             display this help message\n"
            "       -l:             send ctrl-L (refresh) after connecting, default is 1\n"
            "       -a:             start with autohiding on, default is 1\n"
            "\n"
            "       (these usually aren't needed -- defaults are included for ssh, otherwise it will assume stdin and stdout)\n"
            "       -r input_fd:    fd number that the target reads from\n"
            "       -w output_fd:    fd number that the target writes to\n"
            "\n"
            "keyboard shortcuts:\n"
            "   ctrl-a d:       exit (IMPORTANT, as ctrl-c and ctrl-z will be sent to the target)\n"
            "   ctrl-a s:       hide output in the target process\n"
            "   ctrl-a q:       resume output in the target process\n"
            "   ctrl-a h:       toggle autohide mode\n"
            "   ctrl-a ctrl-a:  send an actual ctrl-a to target\n"
            "\n"
            "autohide mode:\n"
            "   this will start hiding output whenever you start typing input,\n"
            "   and resume output whenever the actual user of the target types something\n"
            "\n"
            );
}

void process_args(int argc, char **argv)
{
    int c;

    while (1) {
        c = getopt(argc, argv, "p:hl:a:r:w:");
        switch (c) {
            fprintf(stderr, "hi %c\n", c);
            case 'p': pid = atoi(optarg); break;
            case 'h': usage(); exit(0);
            case 'l':
                      if (!(strcmp(optarg, "0") == 0 || strcmp(optarg, "1") == 0)) {
                          fprintf(stderr, "-l must be 0 or 1\n\n");
                          usage();
                          exit(1);
                      }
                      send_clear = atoi(optarg); break;
            case 'a':
                      if (!(strcmp(optarg, "0") == 0 || strcmp(optarg, "1") == 0)) {
                          fprintf(stderr, "-a must be 0 or 1\n\n");
                          usage();
                          exit(1);
                      }
                      auto_hide = atoi(optarg); break;
            case 'r': read_fd = atoi(optarg); break;
            case 'w': write_fd = atoi(optarg); break;
        }
        if (c == -1)
            break;
    }

    if (!pid) {
        usage();
        exit(1);
    }
}

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

void inject_input(long c)
{
    struct user_regs_struct regs, saved;
    long saved_stack;

    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    /* save the current registers */
    saved = regs;
    /* make the ioctl call with the character copied to rsp */
    regs.ORIG_AX = SYS_ioctl;
    regs.ARG1 = read_fd;
    regs.ARG2 = TIOCSTI;
    regs.ARG3 = regs.SP;
    saved_stack = ptrace(PTRACE_PEEKDATA, pid, regs.SP, 0);
    ptrace(PTRACE_POKEDATA, pid, regs.SP, c);
    ptrace(PTRACE_SETREGS, pid, 0, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    waitpid(pid, NULL, 0);
    /* restore the registers and rsp */
    saved.IP -= 2;
    saved.AX = saved.ORIG_AX;
    ptrace(PTRACE_SETREGS, pid, 0, &saved);
    ptrace(PTRACE_POKEDATA, pid, regs.SP, saved_stack);
}

void handle_input_and_wait_for_syscall()
{
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
                return;
            } else if (WSTOPSIG(status) == SIGSTOP) {
                pthread_mutex_lock(&lock);
                inject_input(forced_input_char);
                forced_input_char = 0;
                pthread_cond_signal(&input_ready);
                pthread_mutex_unlock(&lock);
            }
        }

        if (WIFEXITED(status))
            reset_tty_and_exit(0);
    }
}

/* display output that pid sends to fd */
void* ptrace_target(void *unused)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
        die("couldn't attach to target (are you not root and is /proc/sys/kernel/yama/ptrace_scope 1?)");
    wait(0);

    /* don't want it sending SIGSTOP trying to inject input until attached */
    pthread_mutex_lock(&lock);
    forced_input_char = 0;
    pthread_cond_signal(&input_ready);
    pthread_mutex_unlock(&lock);

    while (1) {
        handle_input_and_wait_for_syscall();

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        /* ssize_t write(int fd, const void *buf, size_t count)
         * fd:   regs.rdi
         * buf:  regs.rsi
         * size: regs.rdx
         */
        if (regs.ORIG_AX == SYS_write && (regs.ARG1 == write_fd || regs.ARG1 == 1)) {
            int i;
            char *buf = malloc(regs.ARG3 + sizeof(long));

            for (i = 0; i < regs.ARG3; i += sizeof(long)) {
                long val = ptrace(PTRACE_PEEKDATA, pid, regs.ARG2 + i, 0);
                memcpy(buf + i, &val, sizeof(long));
            }

            write(1, buf, regs.ARG3);
            free(buf);

            /* discard writes if hidden_flag is set */
            if (is_hidden()) {
                memset(buf, 0, regs.ARG3);
                for (i = 0; i < regs.ARG3; i += sizeof(long))
                    ptrace(PTRACE_POKEDATA, pid, regs.ARG2 + i, *(long *)(buf + i));
            }
        }

        /* return of the syscall */
        handle_input_and_wait_for_syscall();
        if (regs.ORIG_AX == SYS_read && (regs.ARG1 == read_fd || regs.ARG1 == 0)) {
            if (is_hide_counter_zero() && auto_hide)
                unset_hidden();

            ptrace(PTRACE_GETREGS, pid, 0, &regs);
            if (regs.AX >= 0)
                subtract_hide_counter(regs.AX);
        }
    }

    return NULL;
}

/* send input to target */
void send_input(char c)
{
    if (auto_hide) {
        set_hidden();
        increment_hide_counter();
    }
    /* if we have root we can just TIOCSTI,
     * otherwise we need to ptrace and inject the ioctl */
    if (have_root) {
        ioctl(target_tty_fd, TIOCSTI, &c);
    } else {
        pthread_mutex_lock(&lock);
        while (forced_input_char != 0)
            pthread_cond_wait(&input_ready, &lock);
        forced_input_char = c;
        kill(pid, SIGSTOP);
        pthread_mutex_unlock(&lock);
    }
}

int main(int argc, char **argv)
{
    pthread_t ptrace_thread;
    process_args(argc, argv);

    ttySetRaw(STDIN_FILENO, &prev);

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = term;
    sigaction(SIGTERM, &action, NULL);
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigwinchHandler;
    sigaction(SIGWINCH, &action, NULL);

    /* mirror output in another thread */
    pthread_create(&ptrace_thread, NULL, ptrace_target, NULL);

    if (geteuid() == 0)
        have_root = 1;
    else
        have_root = 0;

    char devname[80];
    snprintf(devname, sizeof(devname), "/proc/%d/fd/%d", pid, read_fd);
    target_tty_fd = open(devname, O_WRONLY);

    if (target_tty_fd == -1)
        die("couldn't open target's tty\n");

    /* check that our terminal is large enough for the display we're mirroring */
    check_window_size();

    /* in parent go on to send them our input */
    int c, num_read, i;
    char buf[2048];

    /* send a refresh at the start */
    if (send_clear)
        send_input(0x0c);

    while (1) {
        num_read = read(0, buf, sizeof(buf));

        if (num_read <= 0)
            continue;

        /* ctrl-A */
        if (buf[0] == 0x01) {
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
            else if (c == 0x01)
                send_input(c);
        /* don't send escape reponses */
        } else if(buf[0] != 0x1b) {
            for (i = 0; i < num_read; i++)
                send_input(buf[i]);
        }
    }

    /* wait on ptrace-ing thread to finish */
    pthread_cancel(ptrace_thread);
    pthread_join(ptrace_thread, NULL);

    reset_tty_and_exit(0);
    return 0;
}
