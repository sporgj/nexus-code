#include "compat-layer.h"

static int seed = 1;

int rand() {
  seed = (seed * 32719 + 3) % 32749;
  return seed;
}

void srand(int val) {
  seed = val;
}
