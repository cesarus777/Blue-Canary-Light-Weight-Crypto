#include <assert.h>
#include <stdint.h>
#include <string.h>

enum {
  Nb = 4,
  Nk = 4,
  Nr = 10,
};

enum { SBOX_SIZE = 256 };
static const uint8_t sbox[SBOX_SIZE] = {};

static inline uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  uint8_t counter;
  uint8_t hi_bit_set;

  for (counter = 0; counter < 8; counter++) {
    if ((b & 1) == 1) {
      p ^= a;
    }
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set == 0x80) {
      a ^= 0x1b;
    }
    b >>= 1;
  }

  return p;
}

static void encrypt_round(uint8_t *state, uint8_t *round_keys, int n) {
  assert(state);
  assert(round_keys);
  assert((n > 0) && (n <= Nr));

  uint8_t tmp[4 * Nb];

  // subBytes
  for (int i = 0; i < 4 * Nb; i++) {
    tmp[i] = sbox[state[i]];
  }

  // shiftRows
  for (int i = 1; i < 4; i++) {
    uint8_t swap_buf[4];
    for (int j = 0; j < 3; j++) {
      int offset = i + j * 4;
      swap_buf[i] = tmp[offset];
    }
    for (int j = 0; j < 3; j++) {
      int offset = i + j * 4;
      tmp[offset] = swap_buf[(i + j) & 3];
    }
  }

  if (n != Nr) {
    // mixColums
    for (int i = 0; i < 4; ++i) {
      int offset = 4 * i;
      state[offset + 0] = gmul(2, tmp[offset + 0] ^ tmp[offset + 1]) ^
                          tmp[offset + 1] ^ tmp[offset + 2] ^ tmp[offset + 3];
      state[offset + 1] = gmul(2, tmp[offset + 1] ^ tmp[offset + 2]) ^
                          tmp[offset + 0] ^ tmp[offset + 2] ^ tmp[offset + 3];
      state[offset + 2] = gmul(2, tmp[offset + 2] ^ tmp[offset + 3]) ^
                          tmp[offset + 0] ^ tmp[offset + 1] ^ tmp[offset + 3];
      state[offset + 3] = gmul(2, tmp[offset + 3] ^ tmp[offset + 0]) ^
                          tmp[offset + 0] ^ tmp[offset + 1] ^ tmp[offset + 2];
    }
  }

  // addKey
  for (int i = 0; i < 4 * Nb; i++) {
    state[i] = (n == Nr ? tmp[i] : state[i]) ^ round_keys[4 * Nb * n + i];
  }
}

void encrypt(uint8_t *block, uint8_t *round_keys) {
  assert(block);
  assert(round_keys);

  for (int i = 0; i < 4 * Nb; i++) {
    block[i] ^= round_keys[i];
  }

  for (int i = 1; i <= Nr; i++) {
    encrypt_round(block, round_keys, i);
  }
}
