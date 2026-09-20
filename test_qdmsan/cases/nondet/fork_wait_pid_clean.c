#include <signal.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

volatile long qdmsan_sink_l;

int main(void) {
  pid_t child = fork();
  if (child < 0) return 0;
  if (child == 0) _exit(0);

  int status = 0;
  pid_t waited = waitpid(child, &status, 0);
  if (waited < 0) return 0;
  (void)kill(child, 0);
  qdmsan_sink_l = (long)child ^ ((long)waited << 1) ^ status;
  if (qdmsan_sink_l & 1) return 0;
  return 0;
}
