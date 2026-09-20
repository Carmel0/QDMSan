#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int start_fd[2], done_fd[2], hold_fd[2];
static volatile unsigned char *payload;
static char *worker_count;
static char *exit_mode;

static void *worker(void *unused) {
  char token = 0;
  volatile unsigned branch_sink = 0;
  (void)unused;
  if (read(start_fd[0], &token, 1) != 1) _exit(20);
  unsigned n = worker_count[0] == '1' ? 64 : 0;
  for (unsigned i = 0; i < n; ++i) {
    unsigned char value = payload[i & 7u];
    if (value == 107) branch_sink = 1;
    else branch_sink = 2;
  }
  token = 'd';
  if (write(done_fd[1], &token, 1) != 1) _exit(21);
  if (exit_mode[0] == 'b' || exit_mode[0] == 'r') {
    /* Keep a translated CPU running while main requests exclusive exit or
       fork.  No further conditional checks change the completed payload. */
    for (;;) __asm__ volatile("pause");
  }
  if (read(hold_fd[0], &token, 1) != 1) _exit(22);
  if (exit_mode[0] == 'e') _exit(0);
  return NULL;
}

int main(int argc, char **argv) {
  pthread_t tids[32];
  char token = 's';
  if (argc != 4) return 10;
  unsigned threads = strtoul(argv[3], NULL, 10);
  if (!threads || threads > 32) return 18;
  worker_count = argv[2];
  exit_mode = argv[1];
  payload = malloc(8);
  if (!payload) return 11;
#ifdef DEFINED
  for (unsigned i = 0; i < 8; ++i) payload[i] = (unsigned char)(i + 1);
#endif
  if (pipe(start_fd) || pipe(done_fd) || pipe(hold_fd)) return 12;
  for (unsigned i = 0; i < threads; ++i) {
    if (pthread_create(&tids[i], NULL, worker, NULL)) return 13;
  }
  for (unsigned i = 0; i < threads; ++i) {
    if (write(start_fd[1], &token, 1) != 1) return 14;
  }
  for (unsigned i = 0; i < threads; ++i) {
    if (read(done_fd[0], &token, 1) != 1) return 15;
  }
  if (argv[1][0] == 'f' || argv[1][0] == 'r') {
    pid_t child = fork();
    if (child < 0) return 23;
    if (!child) return 0;
    int status;
    if (waitpid(child, &status, 0) != child || status != 0) return 24;
  }
  if (argv[1][0] == 'e') {
    /* Every worker completed its payload; let one terminate the process
       while main and the remaining workers are still alive. */
    /* No post-release libc RECORD or conditional checkpoint: the worker
       may stop main immediately after the write wakes it. */
    syscall(SYS_write, hold_fd[1], &token, 1);
    for (;;) syscall(SYS_pause);
  }
  if (argv[1][0] == 'j' || argv[1][0] == 'p') {
    for (unsigned i = 0; i < threads; ++i) {
      if (write(hold_fd[1], &token, 1) != 1) return 16;
    }
    if (argv[1][0] == 'p') pthread_exit(NULL);
    for (unsigned i = 0; i < threads; ++i) {
      if (pthread_join(tids[i], NULL)) return 17;
    }
  }
  return 0;
}
