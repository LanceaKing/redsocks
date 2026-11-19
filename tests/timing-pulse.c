/* Keep one test CPU's virtual timer and scheduler responsive during netem. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

int main(void)
{
    const struct sched_param priority = {.sched_priority = 1};
    const struct itimerspec period = {{0, 1000000}, {0, 1000000}};
    struct sigaction action = {.sa_handler = stop};
    struct timespec began, ended;
    struct rusage usage;
    const pid_t parent = getppid();
    uint64_t ticks, expirations = 0, missed = 0;
    int fd;

    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
        sched_setscheduler(0, SCHED_FIFO, &priority)) {
        perror("timing pulse setup (CAP_SYS_NICE required)");
        return 1;
    }
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (fd < 0 || timerfd_settime(fd, 0, &period, NULL)) {
        perror("timing pulse timer");
        return 1;
    }
    /* A stuck parent cannot leave this test helper running indefinitely. */
    alarm(300);
    clock_gettime(CLOCK_MONOTONIC, &began);
    puts("ready");
    fflush(stdout);
    while (!stopping) {
        ssize_t received = read(fd, &ticks, sizeof(ticks));
        if (received < 0 && errno == EINTR)
            continue;
        if (received != (ssize_t)sizeof(ticks)) {
            perror("timing pulse read");
            close(fd);
            return 1;
        }
        expirations += ticks;
        missed += ticks - 1;
    }
    close(fd);
    clock_gettime(CLOCK_MONOTONIC, &ended);
    getrusage(RUSAGE_SELF, &usage);
    fprintf(stderr, "cpu=%d policy=SCHED_FIFO priority=1 period_ns=1000000 "
            "elapsed_ms=%.3f cpu_ms=%.3f expirations=%" PRIu64 " missed=%" PRIu64 "\n",
            sched_getcpu(), (ended.tv_sec-began.tv_sec)*1000.0 +
            (ended.tv_nsec-began.tv_nsec)/1000000.0,
            (usage.ru_utime.tv_sec+usage.ru_stime.tv_sec)*1000.0 +
            (usage.ru_utime.tv_usec+usage.ru_stime.tv_usec)/1000.0,
            expirations, missed);
    return 0;
}
