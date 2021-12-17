#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
  Nb = 4,
  Nk = 4,
  Nr = 10,
  BYTES_IN_COL = sizeof(uint32_t) / sizeof(uint8_t),
  RCON_SIZE = 31,
  SBOX_SIZE = 256,
  INV_SBOX_SIZE = 256,
};

typedef union {
  uint32_t i32;
  uint8_t i8[BYTES_IN_COL];
} word_t;

static const uint8_t rc_tab[Nr];
static const uint8_t keys[BYTES_IN_COL * Nk];
static const uint8_t Rcon[RCON_SIZE];
static const uint8_t sbox[SBOX_SIZE];
static const uint8_t inv_sbox[INV_SBOX_SIZE];

static void rotate_word(word_t *w) {
  uint8_t t = w->i8[0];

  w->i8[0] = w->i8[1];
  w->i8[1] = w->i8[2];
  w->i8[2] = w->i8[3];
  w->i8[3] = t;
}

static void run_key_schedule(const uint8_t *key, uint8_t *round_keys) {
  uint8_t rc = 0;

  word_t tmp;

  memcpy(round_keys, key, BYTES_IN_COL * Nk);

  for (int i = 4; i < 44; ++i) {
    tmp.i32 = ((uint32_t *)(round_keys))[i - 1];
    if (0 == i % 4) {
      rotate_word(&tmp);

      tmp.i8[0] = sbox[tmp.i8[0]];
      tmp.i8[1] = sbox[tmp.i8[1]];
      tmp.i8[2] = sbox[tmp.i8[2]];
      tmp.i8[3] = sbox[tmp.i8[3]];
      tmp.i8[0] ^= rc_tab[rc];
      rc++;
    }
    ((uint32_t *)(round_keys))[i] = ((uint32_t *)(round_keys))[i - 4] ^ tmp.i32;
  }
}

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

static inline void decrypt_round(word_t *state, uint8_t *round_keys, int n) {
  assert(state);
  assert(round_keys);
  assert((n > 0) && (n <= Nr));

  word_t tmp[Nb];
  uint8_t t, u, v, w;

  // keyAdd
  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < BYTES_IN_COL; j++) {
      if (Nr != n)
        tmp[i].i8[j] = state[i].i8[j] ^ round_keys[BYTES_IN_COL * Nb * n + i * BYTES_IN_COL + j];
      else
        state[i].i8[j] ^= round_keys[BYTES_IN_COL * Nb * n + i * BYTES_IN_COL + j];
    }
  }

#ifdef DEBUG_LOG
  fprintf(stderr, "state: ");
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      fprintf(stderr, "0x%02x ", state[i].i8[j]);
  fprintf(stderr, "\n");
#endif

  if (Nr != n) {
    // mixColums
    for (int i = 0; i < Nb; ++i) {
      t = tmp[i].i8[3] ^ tmp[i].i8[2];
      u = tmp[i].i8[1] ^ tmp[i].i8[0];
      v = t ^ u;
      v = gmul(0x09, v);
      w = v ^ gmul(0x04, tmp[i].i8[2] ^ tmp[i].i8[0]);
      v = v ^ gmul(0x04, tmp[i].i8[3] ^ tmp[i].i8[1]);

      state[i].i8[3] =
          tmp[i].i8[3] ^ v ^ gmul(0x02, tmp[i].i8[0] ^ tmp[i].i8[3]);
      state[i].i8[2] = tmp[i].i8[2] ^ w ^ gmul(0x02, t);
      state[i].i8[1] =
          tmp[i].i8[1] ^ v ^ gmul(0x02, tmp[i].i8[2] ^ tmp[i].i8[1]);
      state[i].i8[0] = tmp[i].i8[0] ^ w ^ gmul(0x02, u);

#ifdef DEBUG_LOG
      fprintf(stderr, "%d state: ", i);
      for (int k = 0; k < Nb; k++)
        for (int l = 0; l < BYTES_IN_COL; l++)
          fprintf(stderr, "0x%02x ", state[k].i8[l]);
      fprintf(stderr, "\n");
#endif
    }
  } else {
#ifdef DEBUG_LOG
    fprintf(stderr, "state: ");
    for (int i = 0; i < Nb; i++)
      for (int j = 0; j < BYTES_IN_COL; j++)
        fprintf(stderr, "0x%02x ", state[i].i8[j]);
    fprintf(stderr, "\n");
#endif
  }

  // shiftRows
  for (int i = 1; i < BYTES_IN_COL; i++) {
    uint8_t swap_buf[4];
    for (int j = 0; j < Nb; j++) {
      swap_buf[j] = state[j].i8[i];
    }
    for (int j = 0; j < Nb; j++) {
      state[j].i8[i] = swap_buf[(Nb - i + j) & 3];
    }
#ifdef DEBUG_LOG
    fprintf(stderr, "%d state: ", i);
    for (int k = 0; k < Nb; k++)
      for (int l = 0; l < BYTES_IN_COL; l++)
        fprintf(stderr, "0x%02x ", state[k].i8[l]);
    fprintf(stderr, "\n");
#endif
  }

  // subBytes
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      state[i].i8[j] = inv_sbox[state[i].i8[j]];

#ifdef DEBUG_LOG
  fprintf(stderr, "state: ");
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      fprintf(stderr, "0x%02x ", state[i].i8[j]);
  fprintf(stderr, "\n");
#endif
}

static void decrypt_impl(word_t *block, uint8_t *round_keys) {
  for (int i = Nr; i > 0; i--) {
#ifdef DEBUG_LOG
    fprintf(stderr, "round %2d\n", i);
#endif
    decrypt_round(block, round_keys, i);
  }

  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < BYTES_IN_COL; j++) {
      block[i].i8[j] ^= round_keys[i * BYTES_IN_COL + j];
    }
  }
}

void decrypt(uint8_t *block) {
  uint8_t round_keys[BYTES_IN_COL * Nk * (Nr + 1)];
  run_key_schedule(keys, round_keys);
  decrypt_impl((word_t *)block, round_keys);
}

static void encrypt_round(word_t *state, uint8_t *round_keys, int n) {
  assert(state);
  assert(round_keys);
  assert((n > 0) && (n <= Nr));

  word_t tmp[Nb];

  // subBytes
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      tmp[i].i8[j] = sbox[state[i].i8[j]];

#ifdef DEBUG_LOG
  fprintf(stderr, "  tmp: ");
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      fprintf(stderr, "0x%02x ", tmp[i].i8[j]);
  fprintf(stderr, "\n");
#endif

  // shiftRows
  for (int i = 1; i < BYTES_IN_COL; i++) {
    uint8_t swap_buf[Nb];
    for (int j = 0; j < Nb; j++) {
      swap_buf[j] = tmp[j].i8[i];
    }
    for (int j = 0; j < Nb; j++) {
      tmp[j].i8[i] = swap_buf[(i + j) & 3];
    }
#ifdef DEBUG_LOG
    fprintf(stderr, "%d tmp: ", i);
    for (int k = 0; k < Nb; k++)
      for (int l = 0; l < BYTES_IN_COL; l++)
        fprintf(stderr, "0x%02x ", tmp[k].i8[l]);
    fprintf(stderr, "\n");
#endif
  }

  if (n != Nr) {
    // mixColums
    for (int i = 0; i < Nb; ++i) {
      uint8_t t = tmp[i].i8[0] ^ tmp[i].i8[1] ^ tmp[i].i8[2] ^ tmp[i].i8[3];

      state[i].i8[0] = gmul(2, tmp[i].i8[0] ^ tmp[i].i8[1]) ^ tmp[i].i8[0] ^ t;

      state[i].i8[1] = gmul(2, tmp[i].i8[1] ^ tmp[i].i8[2]) ^ tmp[i].i8[1] ^ t;

      state[i].i8[2] = gmul(2, tmp[i].i8[2] ^ tmp[i].i8[3]) ^ tmp[i].i8[2] ^ t;

      state[i].i8[3] = gmul(2, tmp[i].i8[3] ^ tmp[i].i8[0]) ^ tmp[i].i8[3] ^ t;
#ifdef DEBUG_LOG
      fprintf(stderr, "%d state: ", i);
      for (int k = 0; k < Nb; k++)
        for (int l = 0; l < BYTES_IN_COL; l++)
          fprintf(stderr, "0x%02x ", state[k].i8[l]);
      fprintf(stderr, "\n");
#endif
    }
  } else {
#ifdef DEBUG_LOG
    fprintf(stderr, "state: ");
    for (int i = 0; i < Nb; i++)
      for (int j = 0; j < BYTES_IN_COL; j++)
        fprintf(stderr, "0x%02x ", state[i].i8[j]);
    fprintf(stderr, "\n");
#endif
  }

  // addKey
  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < BYTES_IN_COL; j++) {
      state[i].i8[j] = (n == Nr ? tmp[i].i8[j] : state[i].i8[j]) ^
                       round_keys[BYTES_IN_COL * Nb * n + i * BYTES_IN_COL + j];
    }
  }
#ifdef DEBUG_LOG
  fprintf(stderr, "state: ");
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      fprintf(stderr, "0x%02x ", state[i].i8[j]);
  fprintf(stderr, "\n");
#endif
}

static void encrypt_impl(word_t *block, uint8_t *round_keys) {
  assert(block);
  assert(round_keys);

  for (int i = 0; i < Nb; i++) {
    for (int j = 0; j < BYTES_IN_COL; j++) {
      block[i].i8[j] ^= round_keys[i * BYTES_IN_COL + j];
    }
  }

#ifdef DEBUG_LOG
  fprintf(stderr, "     state: ");
  for (int i = 0; i < Nb; i++)
    for (int j = 0; j < BYTES_IN_COL; j++)
      fprintf(stderr, "0x%02x ", block[i].i8[j]);
  fprintf(stderr, "\n");
#endif

  for (int i = 1; i <= Nr; i++) {
#ifdef DEBUG_LOG
    fprintf(stderr, "round %2d\n", i);
#endif
    encrypt_round(block, round_keys, i);
  }
}

void encrypt(uint8_t *block) {
  assert(block);
  enum { N_ROUND_KEYS = BYTES_IN_COL * Nk * (Nr + 1)};
  uint8_t round_keys[N_ROUND_KEYS];
  run_key_schedule(keys, round_keys);

#ifdef DEBUG_LOG
  fprintf(stderr, "round keys: ");
  for (int i = 0; i < N_ROUND_KEYS; i++)
    fprintf(stderr, "0x%02x ", round_keys[i]);
  fprintf(stderr, "\n");
#endif
  encrypt_impl((word_t *)block, round_keys);
}

static const uint8_t rc_tab[Nr] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                   0x20, 0x40, 0x80, 0x1b, 0x36};

static const uint8_t keys[BYTES_IN_COL * Nk] = {
    0xf5, 0x30, 0x35, 0x79, 0x68, 0x57, 0x84, 0x80,
    0xb3, 0x98, 0xa3, 0xc2, 0x51, 0xcd, 0x10, 0x93};

static const uint8_t Rcon[RCON_SIZE] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xc0, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

static const uint8_t sbox[SBOX_SIZE] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t inv_sbox[INV_SBOX_SIZE] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d,
};
