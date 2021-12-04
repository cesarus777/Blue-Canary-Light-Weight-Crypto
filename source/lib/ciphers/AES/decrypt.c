#include <assert.h>
#include <stdint.h>

enum {
  Nb = 4,
  Nk = 4,
  Nr = 10,
};

enum { INV_SBOX_SIZE = 256 };
static const uint8_t inv_sbox[INV_SBOX_SIZE] = {};

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

static inline void decrypt_round(uint8_t *state, uint8_t *round_keys, int n) {
  assert(state);
  assert(round_keys);
  assert((n > 0) && (n <= Nr));

  uint8_t tmp[4 * Nb];
  uint8_t t, u, v, w;

  // keyAdd
  for (int i = 0; i < 16; ++i) {
    if (Nr != 10)
      tmp[i] = state[i] ^ round_keys[i];
    else
      state[i] ^= round_keys[i];
  }

  if (Nr != 10) {
    // mixColums
    for (int i = 0; i < 4; ++i) {
      t = tmp[4 * i + 3] ^ tmp[4 * i + 2];
      u = tmp[4 * i + 1] ^ tmp[4 * i + 0];
      v = t ^ u;
      v = gmul(0x09, v);
      w = v ^ gmul(0x04, tmp[4 * i + 2] ^ tmp[4 * i + 0]);
      v = v ^ gmul(0x04, tmp[4 * i + 3] ^ tmp[4 * i + 1]);

      state[4 * i + 3] =
          tmp[4 * i + 3] ^ v ^ gmul(0x02, tmp[4 * i + 0] ^ tmp[4 * i + 3]);
      state[4 * i + 2] = tmp[4 * i + 2] ^ w ^ gmul(0x02, t);
      state[4 * i + 1] =
          tmp[4 * i + 1] ^ v ^ gmul(0x02, tmp[4 * i + 2] ^ tmp[4 * i + 1]);
      state[4 * i + 0] = tmp[4 * i + 0] ^ w ^ gmul(0x02, u);
    }
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
      tmp[offset] = swap_buf[(4 - i + j) & 3];
    }
  }

  // subBytes
  for (int i = 0; i < 16; ++i) {
    state[i] = inv_sbox[state[i]];
  }
}

void decrypt(uint8_t *block, uint8_t *round_keys) {
  for (int i = 10; i > 0; i--) {
    decrypt_round(block, round_keys, i);
  }
}
