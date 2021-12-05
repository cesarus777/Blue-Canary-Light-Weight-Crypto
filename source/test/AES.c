#include "ciphers/AES.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main() {
  uint8_t message[16] = {};

#ifdef DEBUG_LOG
  printf("msg: ");
  for (int i = 0; i < 16; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  encrypt(message);

#ifdef DEBUG_LOG
  printf("encrypted msg: ");
  for (int i = 0; i < 16; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  uint8_t expected_ciphertext[16] = {0xf5, 0xdf, 0x39, 0x99, 0x0f, 0xc6,
                                     0x88, 0xf1, 0xb0, 0x72, 0x24, 0xcc,
                                     0x03, 0xe8, 0x6c, 0xea};

  for (int i = 0; i < 16; i++) {
    assert(message[i] == expected_ciphertext[i] && "bad encryption");
  }

  decrypt(message);

#ifdef DEBUG_LOG
  printf("decrypted msg: ");
  for (int i = 0; i < 16; i++) {
    printf("0x%02x ", message[i]);
  }
  printf("\n");
#endif

  for (int i = 0; i < 16; i++) {
    assert(message[i] == 0x00 && "bad decryption");
  }
}
