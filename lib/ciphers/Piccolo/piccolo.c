#include "piccolo.h"
#include <stdint.h>



SBOX_BYTE SBOX[] ={0x0e, 0x04, 0x0b, 0x02,0x03, 0x08, 0x00, 0x09,0x01, 0x0a, 0x07, 0x0f,0x06, 0x0c, 0x05, 0x0d};

/* GF[2^4] multiplication by 2 */
GF16_MUL_BYTE GF16_MUL2[] = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,0x03, 0x01, 0x07, 0x05, 0x0b, 0x09, 0x0f, 0x0d};

/* GF[2^4] multiplication by 3 */
GF16_MUL_BYTE GF16_MUL3[] = {0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02};


uint8_t polyEval(uint8_t p0, uint8_t p1, uint8_t p2, uint8_t p3)
{
    /* uint8_t y = p0 ^ p1 ^ gf16_mul2(p2) ^ gf16_mul3(p3); */
    uint8_t y = p0 ^ p1 ^ READ_GF16_MUL_BYTE(GF16_MUL2[p2]) ^ READ_GF16_MUL_BYTE(GF16_MUL3[p3]);

    return y;
}

uint16_t F(uint16_t x)
{
    uint8_t x0;
    uint8_t x1;
    uint8_t x2;
    uint8_t x3;
    uint8_t y0;
    uint8_t y1;
    uint8_t y2;
    uint8_t y3;


    x3 = (x >>  0) & 0x0f;
    x2 = (x >>  4) & 0x0f;
    x1 = (x >>  8) & 0x0f;
    x0 = (x >> 12) & 0x0f;

    x3 = READ_SBOX_BYTE(SBOX[x3]);
    x2 = READ_SBOX_BYTE(SBOX[x2]);
    x1 = READ_SBOX_BYTE(SBOX[x1]);
    x0 = READ_SBOX_BYTE(SBOX[x0]);

    y0 = polyEval(x2, x3, x0, x1);
    y1 = polyEval(x3, x0, x1, x2);
    y2 = polyEval(x0, x1, x2, x3);
    y3 = polyEval(x1, x2, x3, x0);
    y0 = READ_SBOX_BYTE(SBOX[y0]);
    y1 = READ_SBOX_BYTE(SBOX[y1]);
    y2 = READ_SBOX_BYTE(SBOX[y2]);
    y3 = READ_SBOX_BYTE(SBOX[y3]);

    return (y0 << 12) | (y1 << 8) | (y2 << 4) | y3;
}

void RP(uint16_t *x0, uint16_t *x1, uint16_t *x2, uint16_t *x3)
{
    uint16_t y0;
    uint16_t y1;
    uint16_t y2;
    uint16_t y3;


    y0 = (*x1 & 0xff00) | (*x3 & 0x00ff);
    y1 = (*x2 & 0xff00) | (*x0 & 0x00ff);
    y2 = (*x3 & 0xff00) | (*x1 & 0x00ff);
    y3 = (*x0 & 0xff00) | (*x2 & 0x00ff);

    *x0 = y0;
    *x1 = y1;
    *x2 = y2;
    *x3 = y3;
}

void keySchedule(BYTE x[], KEY *k) {

    /* init whitening keys */
    k->wKey[0] = 0x0;
    k->wKey[1] = 0x0;

    /* init round keys */
    int i;
    for (i = 0; i < RN; i++) {
        k->rKey[i] = 0x0;
        //printf("i = \n", i);
    }

    /* compute keys */
    if (KEYSIZE == 80) {

        /* set whitening keys */
        k->wKey[0] ^= (x[0] << 24);
        k->wKey[0] ^= (x[3] << 16);
        k->wKey[0] ^= (x[2] <<  8);
        k->wKey[0] ^= (x[1] <<  0);

        k->wKey[1] ^= (x[8] << 24);
        k->wKey[1] ^= (x[7] << 16);
        k->wKey[1] ^= (x[6] <<  8);
        k->wKey[1] ^= (x[9] <<  0);

        /* set round keys */
        int r = 0;
        for (r = 0; r < RN; r++) {

            /* generates the constants */
            //k->rKey[r] ^= ((r+1) << 27) ^ ((r+1) << 17) ^ ((r+1) << 10) ^ ((r+1) << 0) ^ 0x0F1E2D3C;
            //printf("%08x\n", k->rKey[r]);

            /* use precomputed constants */
            k->rKey[r] ^= C[r];

            if ( r%5 == 0 || r%5 == 2 ) {
                k->rKey[r] ^= (x[4] << 24) ^ (x[5] << 16) ^ (x[6] << 8) ^ (x[7] << 0);
            } else if ( r%5 == 1 || r%5 == 4 ) {
                k->rKey[r] ^= (x[0] << 24) ^ (x[1] << 16) ^ (x[2] << 8) ^ (x[3] << 0);
            } else if (r%5 == 3) {
                k->rKey[r] ^= (x[8] << 24) ^ (x[9] << 16) ^ (x[8] << 8) ^ (x[9] << 0);
            }
        }

    } else if (KEYSIZE == 128) {

        /* set whitening keys */
        k->wKey[0] ^= (x[ 0] << 24);
        k->wKey[0] ^= (x[ 3] << 16);
        k->wKey[0] ^= (x[ 2] <<  8);
        k->wKey[0] ^= (x[ 1] <<  0);

        k->wKey[1] ^= (x[ 8] << 24);
        k->wKey[1] ^= (x[15] << 16);
        k->wKey[1] ^= (x[14] <<  8);
        k->wKey[1] ^= (x[ 9] <<  0);

        int r = 0;
        /* init buffer */
        BYTE y[N];
        for (r = 0; r < N; r++) {
            y[r] = x[r];
        }

        /* generates the constants
        for (r = 0; r < RN; r++) {
          k->rKey[r] ^= ((r+1) << 27) ^ ((r+1) << 17) ^ ((r+1) << 10) ^ ((r+1) << 0)  ^ 0x6547A98B;
          printf("%08x\n", k->rKey[r]);
        }
        */

        for (r = 0; r < 2*RN; r++) {
            int c = (r+2)%8;
            if (c == 0) {
                y[ 0] = x[ 4]; y[ 1] = x[ 5]; // k_0 = k_2
                y[ 2] = x[ 2]; y[ 3] = x[ 3]; // k_1 = k_1
                y[ 4] = x[12]; y[ 5] = x[13]; // k_2 = k_6
                y[ 6] = x[14]; y[ 7] = x[15]; // k_3 = k_7
                y[ 8] = x[ 0]; y[ 9] = x[ 1]; // k_4 = k_0
                y[10] = x[ 6]; y[11] = x[ 7]; // k_5 = k_3
                y[12] = x[ 8]; y[13] = x[ 9]; // k_6 = k_4
                y[14] = x[10]; y[15] = x[11]; // k_7 = k_5

                /* update x */
                int i = 0;
                for (i = 0; i < N; i++) {
                    x[i] = y[i];
                }
            }
            if (r%2 == 0) {
                k->rKey[r/2] ^= (C[r/2] & 0xffff0000) ^ (y[2*c] << 24) ^ (y[2*c+1] << 16);
            } else {
                k->rKey[r/2] ^= (C[r/2] & 0x0000ffff) ^ (y[2*c] << 8) ^ (y[2*c+1] << 0);
            }
        }
    }
}

/* galois multiplication in F_16 */
BYTE gm(BYTE a, BYTE b) {
    BYTE g = 0;
    int i;
    for (i = 0; i < DEG_GF_POLY; i++) {
        if ( (b & 0x1) == 1 ) { g ^= a; }
        BYTE hbs = (a & 0x8);
        a <<= 0x1;
        if ( hbs == 0x8) { a ^= GF_POLY; }
        b >>= 0x1;
    }
    return g;
}

void encrypt(uint8_t *block, uint8_t *roundKeys)
{

    KEY k;
    int KEYS[] = {1128877898,520816397,1397573448,18446744072225797537,654646026,2068271949,
                  922817288,190540611,18446744072897266092,1595614981,324888384,1863794435,592543558,
                  18446744073568755115,1997615872,3412790107,2267892510,3681485657,18446744069945289142,
                  2938593051,3814793054,3206764313,4083488604,18446744070617810365,3342691094,};
    for (int i = 0; i < RN; i++) {
        //   k->rKey[i] = 0x0;
        k.rKey[i] = KEYS[i];
    }
    //k.rKey[0] = (unsigned long) 74;//1128877898;
   // k.rKey[1] =   (unsigned long) 79;//520816397;
   // printf("%d\n",roundKeys[0]);
    //printf("%d\n",roundKeys[1]);

    uint8_t i;
    uint16_t *x3 = (uint16_t *)block;
    uint16_t *x2 = x3 + 1;
    uint16_t *x1 = x3 + 2;
    uint16_t *x0 = x3 + 3;
    uint16_t *rk = (uint16_t *) k.rKey;

    *x2 ^= READ_ROUND_KEY_WORD(rk[51]); //
    *x0 ^= READ_ROUND_KEY_WORD(rk[50]);
    for (i = 0; i < NUMBER_OF_ROUNDS - 1; ++i)
    {
        *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2 * i]);
        *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2 * i + 1]);
        RP(x0, x1, x2, x3);
    }
    *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2]);
    *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 1]);
    *x0 ^= READ_ROUND_KEY_WORD(rk[52]);
    *x2 ^= READ_ROUND_KEY_WORD(rk[53]);
}

void decrypt(uint8_t *block, uint8_t *roundKeys)
{



    KEY k;
    int KEYS[] = {1128877898,520816397,1397573448,18446744072225797537,654646026,2068271949,
                  922817288,190540611,18446744072897266092,1595614981,324888384,1863794435,592543558,
                  18446744073568755115,1997615872,3412790107,2267892510,3681485657,18446744069945289142,
                  2938593051,3814793054,3206764313,4083488604,18446744070617810365,3342691094,};
    for (int i = 0; i < RN; i++) {
        //   k->rKey[i] = 0x0;
        k.rKey[i] = KEYS[i];
    }
    uint8_t i;
    uint16_t *x3 = (uint16_t *)block;
    uint16_t *x2 = x3 + 1;
    uint16_t *x1 = x3 + 2;
    uint16_t *x0 = x3 + 3;
    uint16_t *rk = (uint16_t *)k.rKey;

    *x2 ^= READ_ROUND_KEY_WORD(rk[53]);
    *x0 ^= READ_ROUND_KEY_WORD(rk[52]);
    for (i = 0; i < NUMBER_OF_ROUNDS - 1; ++i)
    {
        if ((i & 0x01) == 0)
        {
            *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 2]);
            *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 1]);
        }
        else
        {
            *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 1]);
            *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[2*NUMBER_OF_ROUNDS - 2*i - 2]);
        }
        RP(x0, x1, x2, x3);
    }
    *x1 = *x1 ^ F(*x0) ^ READ_ROUND_KEY_WORD(rk[0]);
    *x3 = *x3 ^ F(*x2) ^ READ_ROUND_KEY_WORD(rk[1]);
    *x0 ^= READ_ROUND_KEY_WORD(rk[50]);
    *x2 ^= READ_ROUND_KEY_WORD(rk[51]);
}
