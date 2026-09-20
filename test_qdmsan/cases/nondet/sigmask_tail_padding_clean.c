#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>

int main(void) {
  sigset_t set;

  ((unsigned long *)&set)[0] = 0;
  if (pthread_sigmask(SIG_SETMASK, &set, 0) != 0) return 1;

  ((unsigned long *)&set)[0] = 0;
  if (sigprocmask(SIG_SETMASK, &set, 0) != 0) return 2;

  return 0;
}
