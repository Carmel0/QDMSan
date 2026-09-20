#include <stdint.h>

volatile int qdmsan_static_stack_sink;

int main(void) {
  volatile uint8_t value;
  qdmsan_static_stack_sink = (value == 7);
  return 0;
}
