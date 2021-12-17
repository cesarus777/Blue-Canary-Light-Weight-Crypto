#include "cipher_interface.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DEBUG_LOG

enum { CHECK_LIM = 8 };

int main() {
  uint8_t message[16] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01};

#ifdef DEBUG_LOG
  printf("msg: ");
  for (int i = 0; i < CHECK_LIM; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  encrypt(message);

#ifdef DEBUG_LOG
  printf("encrypted msg: ");
  for (int i = 0; i < CHECK_LIM; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  uint8_t expected_ciphertext[16] = {0x56, 0x40, 0xf8, 0x35,
                                     0x99, 0xff, 0x2b, 0x8d};

  for (int i = 0; i < CHECK_LIM; i++) {
    assert(message[i] == expected_ciphertext[i] && "bad encryption");
  }

  decrypt(message);

#ifdef DEBUG_LOG
  printf("decrypted msg: ");
  for (int i = 0; i < CHECK_LIM; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  for (int i = 0; i < CHECK_LIM; i++) {
    assert(message[i] == 0x00 && "bad decryption");
  }
}
