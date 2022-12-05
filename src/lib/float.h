#ifndef __LIB_FLOAT_H
#define __LIB_FLOAT_H

#define E_VAL 2.718281
#define TOL 0.000002

/* Pushes integer num to the FPU */
static inline void fpu_push(int num) {
  unsigned char fpu[108];
  asm("fsave %0;" : : "m"(fpu));
  int status_word = fpu[4];
  fpu[28 + status_word * 10] = (float)num;
  if (status_word == 7)
    status_word = 0;
  else
    ++status_word;
  fpu[4] = status_word;
  asm("frstor %0;" : : "m"(fpu));
}

/* Pops integer from the FPU */
static inline int fpu_pop(void) {
  int val;
  unsigned char fpu[108];
  asm("fsave %0;" : : "m"(fpu));
  int status_word = fpu[4];
  if (status_word == 0)
    status_word = 7;
  else
    status_word--;
  val = fpu[28 + status_word * 10];
  fpu[4] = status_word;
  asm("frstor %0;" : : "m"(fpu));
  return val;
}

int sys_sum_to_e(int);
double sum_to_e(int);
double abs_val(double);

#endif /* lib/debug.h */
