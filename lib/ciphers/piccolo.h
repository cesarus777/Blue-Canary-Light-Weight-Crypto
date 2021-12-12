#ifndef PICCOLO_H_
#define PICCOLO_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#if     PICCOLO==80
#define KEYSIZE       80
#define RN            25
#define N             10
#elif   PICCOLO==128
#define KEYSIZE       128
#define RN            31
#define N             16
#endif
#define NUMBER_OF_ROUNDS 25
#define NUMBER_OF_ROUNDS 25
#define BLOCK_SIZE    64
#define GF_POLY       0x13 /* irred. polynomial f = x^4+x+1 for F_16 = F_2[x]/(f) */
#define DEG_GF_POLY   4

typedef unsigned char BYTE; /* 8 bit */
typedef unsigned long WORD; /* 32 bit */


/* key */
typedef struct {
    WORD wKey[2]; /* whitening keys: wKey[0] = w_0 | w_1, wKey[1] = w_2 | w_3 */
    WORD rKey[RN]; /* round keys: 2 round keys are encoded in a 32-bit word */
} KEY;


/* 64-bit state */
typedef struct {
    WORD b[2];
} STATE;


/* function definitions */
void keySchedule(BYTE x[], KEY *k);
void encrypt(STATE *s, KEY *k);
void f(BYTE b[]);
void rp(STATE *s);
BYTE gm(BYTE a, BYTE b);



#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE
#define CON80_DOUBLE_WORD ROM_DATA_DOUBLE_WORD
#define READ_CON80_DOUBLE_WORD READ_ROM_DATA_DOUBLE_WORD
#define GF16_MUL_BYTE ROM_DATA_BYTE
#define READ_GF16_MUL_BYTE READ_ROM_DATA_BYTE

/* the Piccolo SBox */
BYTE SBox[16] = {
        0xE, 0x4, 0xB, 0x2, 0x3, 0x8, 0x0, 0x9,
        0x1, 0xA, 0x7, 0xF, 0x6, 0xC, 0x5, 0xD
};


/* the diffusion matrix */
const BYTE M[4][4] = {
        {0x2,0x3,0x1,0x1},
        {0x1,0x2,0x3,0x1},
        {0x1,0x1,0x2,0x3},
        {0x3,0x1,0x1,0x2},
};


/* constants for the key schedule */
#if KEYSIZE==80
const WORD C[RN] = {
  0x071c293d, 0x1f1a253e, 0x1718213f, 0x2f163d38, 0x27143939,
  0x3f12353a, 0x3710313b, 0x4f0e0d34, 0x470c0935, 0x5f0a0536,
  0x57080137, 0x6f061d30, 0x67041931, 0x7f021532, 0x77001133,
  0x8f3e6d2c, 0x873c692d, 0x9f3a652e, 0x9738612f, 0xaf367d28,
  0xa7347929, 0xbf32752a, 0xb730712b, 0xcf2e4d24, 0xc72c4925
};
#elif KEYSIZE==128
const WORD C[RN] = {
  0x6d45ad8a, 0x7543a189, 0x7d41a588, 0x454fb98f, 0x4d4dbd8e,
  0x554bb18d, 0x5d49b58c, 0x25578983, 0x2d558d82, 0x35538181,
  0x3d518580, 0x055f9987, 0x0d5d9d86, 0x155b9185, 0x1d599584,
  0xe567e99b, 0xed65ed9a, 0xf563e199, 0xfd61e598, 0xc56ff99f,
  0xcd6dfd9e, 0xd56bf19d, 0xdd69f59c, 0xa577c993, 0xad75cd92,
  0xb573c191, 0xbd71c590, 0x857fd997, 0x8d7ddd96, 0x957bd195,
  0x9d79d594
};
#endif
#endif /* PICCOLO_H_ */

/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and
 * Yann Le Corre <yann.lecorre@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CIPHER_H
#define CIPHER_H


#ifdef AVR /* AVR */
#include <avr/pgmspace.h>
#endif /* AVR */


/*
 *
 * Optimization levels
 * ... OPTIMIZATION_LEVEL_0 - O0
 * ... OPTIMIZATION_LEVEL_1 - O1
 * ... OPTIMIZATION_LEVEL_2 - O2
 * ... OPTIMIZATION_LEVEL_3 - O3 = defualt
 *
 */
#define OPTIMIZATION_LEVEL_0 __attribute__((optimize("O0")))
#define OPTIMIZATION_LEVEL_1 __attribute__((optimize("O1")))
#define OPTIMIZATION_LEVEL_2 __attribute__((optimize("O2")))
#define OPTIMIZATION_LEVEL_3 __attribute__((optimize("O3")))


/*
 *
 * SCENARIO values:
 * ... SCENARIO_0 0 - cipher operation: encrypt & decrypt one data block
 * ... SCENARIO_1 1 - scenario 1: encrypt & decrypt data in CBC mode
 * ... SCENARIO_2 2 - scenario 2: encrypt & decrypt data in CTR mode
 *
 */
#define SCENARIO_0 0
#define SCENARIO_1 1
#define SCENARIO_2 2

#ifndef SCENARIO
#define SCENARIO SCENARIO_0
#endif


/*
 *
 * MEASURE_CYCLE_COUNT values:
 * ... MEASURE_CYCLE_COUNT_DISABLED 0 - measure cycle count is disabled
 * ... MEASURE_CYCLE_COUNT_ENABLED 1 - measure cycle count is enabled
 *
 */
#define MEASURE_CYCLE_COUNT_DISABLED 0
#define MEASURE_CYCLE_COUNT_ENABLED 1

#ifndef MEASURE_CYCLE_COUNT
#define MEASURE_CYCLE_COUNT MEASURE_CYCLE_COUNT_DISABLED
#endif


/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_PC_BOUNDRY 64
#define ALIGN_AVR_BOUNDRY 2
#define ALIGN_MSP_BOUNDRY 2
#define ALIGN_ARM_BOUNDRY 8

#if defined(PC) && !defined(ALIGNED) /* PC ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_PC_BOUNDRY)))
#endif /* PC ALIGNED */

#if defined(AVR) && !defined(ALIGNED) /* AVR ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_AVR_BOUNDRY)))
#endif /* AVR ALIGNED */

#if defined(MSP) && !defined(ALIGNED) /* MSP ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_MSP_BOUNDRY)))
#endif /* MSP ALIGNED */

#if defined(ARM) && !defined(ALIGNED) /* ARM ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))
#endif /* ARM ALIGNED */


/*
 *
 * RAM data types
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/*
 *
 * Flash/ROM data types
 *
 */
#if defined(AVR) /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)
#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x
#endif /* AVR */


/*
 *
 * Scenario 2 round keys are stored in Flash/ROM
 *
 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define READ_ROUND_KEY_BYTE(x) READ_ROM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_ROM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_ROM_DATA_DOUBLE_WORD(x)
#else
#define READ_ROUND_KEY_BYTE(x) READ_RAM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_RAM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_RAM_DATA_DOUBLE_WORD(x)
#endif


/*
 *
 * Run the encryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the encryption round keys
 *
 */
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);

/*
 *
 * Run the decryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the decryption round keys
 *
 */
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);


/*
 *
 * Encrypt the given block using the given round keys
 * ... block - the block to encrypt
 * ... roundKeys - the round keys to be used during encryption
 *
 */
//void Encrypt(uint8_t *block);//, uint8_t *roundKeys);

/*
 *
 * Decrypt the given block using the given round keys
 * ... block - the block to decrypt
 * ... roundKeys - the round keys to be used during decryption
 *
 */
//void Decrypt(uint8_t *block);//, uint8_t *roundKeys);

#endif /* CIPHER_H */
