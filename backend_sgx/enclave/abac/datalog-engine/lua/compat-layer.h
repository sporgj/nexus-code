#pragma once

#define luai_makeseed rand

typedef struct {} FILE;

int rand();

void srand(int val);
