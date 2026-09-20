#include <random>

int main() {
  std::random_device rd;
  unsigned x = rd();
  volatile double entropy = rd.entropy();
  volatile unsigned sink = x;
  return (sink == 0x12345678U) || (entropy < 0.0);
}
