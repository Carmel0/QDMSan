#include <sys/ipc.h>
#include <sys/shm.h>

volatile int qdmsan_sink_i32;

int main(void) {
  int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
  if (id < 0) return 0;
  unsigned char *p = shmat(id, 0, 0);
  if (p == (void *)-1) {
    shmctl(id, IPC_RMID, 0);
    return 0;
  }
  p[0] = 0x5a;
  qdmsan_sink_i32 ^= p[0];
  shmdt(p);
  qdmsan_sink_i32 = id;
  shmctl(id, IPC_RMID, 0);
  if (qdmsan_sink_i32 & 1) return 0;
  return 0;
}
