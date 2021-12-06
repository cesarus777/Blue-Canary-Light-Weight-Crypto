#include "cipher_interface.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

enum { N_ITERATIONS = 1000000 };

int main() {
  uint8_t msg[16] = {};

  clock_t encrypt_time = 0;
  clock_t decrypt_time = 0;
  for (int i = 0; i < N_ITERATIONS; i++) {
    clock_t start = clock();
    encrypt(msg);
    clock_t finish = clock();
    encrypt_time += finish - start;

    start = clock();
    decrypt(msg);
    finish = clock();
    decrypt_time += finish - start;
  }

  double encrypt_time_in_seconds = encrypt_time / (double) CLOCKS_PER_SEC;
  double decrypt_time_in_seconds = decrypt_time / (double) CLOCKS_PER_SEC;

  printf("%lf %lf\n", encrypt_time_in_seconds, decrypt_time_in_seconds);
}
