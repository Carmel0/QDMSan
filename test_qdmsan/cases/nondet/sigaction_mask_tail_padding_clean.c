#define _GNU_SOURCE
#include <signal.h>

int main(void) {
  struct sigaction act;

  act.sa_handler = SIG_IGN;
  ((unsigned long *)&act.sa_mask)[0] = 0;
  act.sa_flags = 0;
  if (sigaction(SIGUSR1, &act, 0) != 0) return 1;
  return 0;
}
