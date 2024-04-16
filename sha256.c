/*
 * sha256 - a size tuneable SHA-256 implementation
 * Copyright (C) 2018-2023 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of sha256
 *
 * sha256 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sha256 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sha256.h"

typedef unsigned int sha256_bt;
struct sha256 {
 sha256_bt s[8];       /* unsigned 32 bits */
 sha256_bt bh;         /* bytes processed high */
 sha256_bt bl;         /* bytes processed low */
 unsigned int l;       /* current short data */
 unsigned char d[64];  /* short data */
};

unsigned int
sha256tsize(
  void
){
  return (sizeof (sha256_t));
}

void
sha256init(
  sha256_t *v
){
  v->s[0] = 0x6a09e667U;
  v->s[1] = 0xbb67ae85U;
  v->s[2] = 0x3c6ef372U;
  v->s[3] = 0xa54ff53aU;
  v->s[4] = 0x510e527fU;
  v->s[5] = 0x9b05688cU;
  v->s[6] = 0x1f83d9abU;
  v->s[7] = 0x5be0cd19U;
  v->bh = v->bl = 0;
  v->l = 0;
}

#ifndef SHA256_SPACETIME
/* 1 operator functions (most compilers will inline) */
/* 2 operator macros */
/* 3 don't needlessly copy in loop, size ~14% larger ~10% faster */
/* 4 don't needlessly copy the start and end, size ~44% larger ~15% faster */
#define SHA256_SPACETIME 4
#endif

#if SHA256_SPACETIME == 1

static sha256_bt
RR(
 sha256_bt x
,sha256_bt y
){
  return (((x >> y) | (x << (sizeof (x) * 8 - y))));
}
static sha256_bt
CH(
 sha256_bt x
,sha256_bt y
,sha256_bt z
){
  /* straight out of FIPS PUB 180-4 */
  /* ((x & y) ^ ((~x) & z)) */
  return (((x & (y ^ z)) ^ z)); /* one less operation by boolean reduction */
}
static sha256_bt
MJ(
 sha256_bt x
,sha256_bt y
,sha256_bt z
){
  /* straight out of FIPS PUB 180-4 */
  /* ((x & y) ^ (x & z) ^ (y & z)) */
  return (((x & (y | z)) | (y & z))); /* one less operation by boolean reduction */
}
static sha256_bt
S0(
 sha256_bt x
){
  return (((RR(x,  2)) ^ (RR(x, 13)) ^ (RR(x, 22))));
}
static sha256_bt
S1(
 sha256_bt x
){
  return (((RR(x,  6)) ^ (RR(x, 11)) ^ (RR(x, 25))));
}
static sha256_bt
E0(
 sha256_bt x
){
  return (((RR(x,  7)) ^ (RR(x, 18)) ^ (x >>  3)));
}
static sha256_bt
E1(
 sha256_bt x
){
  return (((RR(x, 17)) ^ (RR(x, 19)) ^ (x >> 10)));
}

#else

#define RR(x,y) ((x >> y) | (x << (sizeof (x) * 8 - y)))
#define CH(x,y,z) ((x & (y ^ z)) ^ z)
#define MJ(x,y,z) ((x & (y | z)) | (y & z))
#define S0(x) ((RR(x,  2)) ^ (RR(x, 13)) ^ (RR(x, 22)))
#define S1(x) ((RR(x,  6)) ^ (RR(x, 11)) ^ (RR(x, 25)))
#define E0(x) ((RR(x,  7)) ^ (RR(x, 18)) ^ (x >>  3))
#define E1(x) ((RR(x, 17)) ^ (RR(x, 19)) ^ (x >> 10))

#endif

static void
sha256mix(
  sha256_bt s[]
 ,unsigned char *d
){
  static sha256_bt k[] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U
   ,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U
   ,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU
   ,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U
   ,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U
   ,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U
   ,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U
   ,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
  };
  sha256_bt w[64];
  sha256_bt t[8];
  unsigned int i;

  for (i = 0; i < 16; ++i, d += 4)
    w[i] = *(d + 0) << (3 * 8)
         | *(d + 1) << (2 * 8)
         | *(d + 2) << (1 * 8)
         | *(d + 3) << (0 * 8);
  for (; i < 64; ++i)
    w[i] = E1(w[i - 2]) + w[i - 7] + E0(w[i - 15]) + w[i - 16];

#if SHA256_SPACETIME == 1 || SHA256_SPACETIME == 2 /* straight out of FIPS PUB 180-4 */

#define A t[0]
#define B t[1]
#define C t[2]
#define D t[3]
#define E t[4]
#define F t[5]
#define G t[6]
#define H t[7]
  A = s[0];
  B = s[1];
  C = s[2];
  D = s[3];
  E = s[4];
  F = s[5];
  G = s[6];
  H = s[7];
  for (i = 0; i < 64; ++i) {
    sha256_bt t1, t2;

    t1 = H + S1(E) + CH(E,F,G) + k[i] + w[i];
    t2 = S0(A) + MJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + t1;
    D = C;
    C = B;
    B = A;
    A = t1 + t2;
  }
  s[0] += A;
  s[1] += B;
  s[2] += C;
  s[3] += D;
  s[4] += E;
  s[5] += F;
  s[6] += G;
  s[7] += H;
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

#endif
#if SHA256_SPACETIME == 3 /* don't needlessly copy in loop */

  t[0] = s[0];
  t[1] = s[1];
  t[2] = s[2];
  t[3] = s[3];
  t[4] = s[4];
  t[5] = s[5];
  t[6] = s[6];
  t[7] = s[7];
  for (i = 0; i < 64; i += 8) {
    t[7] += S1(t[4]) + CH(t[4], t[5], t[6]) + k[i + 0] + w[i + 0];
    t[3] += t[7];
    t[7] += S0(t[0]) + MJ(t[0], t[1], t[2]);
    t[6] += S1(t[3]) + CH(t[3], t[4], t[5]) + k[i + 1] + w[i + 1];
    t[2] += t[6];
    t[6] += S0(t[7]) + MJ(t[7], t[0], t[1]);
    t[5] += S1(t[2]) + CH(t[2], t[3], t[4]) + k[i + 2] + w[i + 2];
    t[1] += t[5];
    t[5] += S0(t[6]) + MJ(t[6], t[7], t[0]);
    t[4] += S1(t[1]) + CH(t[1], t[2], t[3]) + k[i + 3] + w[i + 3];
    t[0] += t[4];
    t[4] += S0(t[5]) + MJ(t[5], t[6], t[7]);
    t[3] += S1(t[0]) + CH(t[0], t[1], t[2]) + k[i + 4] + w[i + 4];
    t[7] += t[3];
    t[3] += S0(t[4]) + MJ(t[4], t[5], t[6]);
    t[2] += S1(t[7]) + CH(t[7], t[0], t[1]) + k[i + 5] + w[i + 5];
    t[6] += t[2];
    t[2] += S0(t[3]) + MJ(t[3], t[4], t[5]);
    t[1] += S1(t[6]) + CH(t[6], t[7], t[0]) + k[i + 6] + w[i + 6];
    t[5] += t[1];
    t[1] += S0(t[2]) + MJ(t[2], t[3], t[4]);
    t[0] += S1(t[5]) + CH(t[5], t[6], t[7]) + k[i + 7] + w[i + 7];
    t[4] += t[0];
    t[0] += S0(t[1]) + MJ(t[1], t[2], t[3]);
  }
  s[0] += t[0];
  s[1] += t[1];
  s[2] += t[2];
  s[3] += t[3];
  s[4] += t[4];
  s[5] += t[5];
  s[6] += t[6];
  s[7] += t[7];

#endif
#if SHA256_SPACETIME == 4 /* don't needlessly copy the start and end */

  t[7]  = s[7] + S1(s[4]) + CH(s[4], s[5], s[6]) + k[0] + w[0];
  t[3]  = s[3] + t[7];
  t[7] += S0(s[0]) + MJ(s[0], s[1], s[2]);

  t[6]  = s[6] + S1(t[3]) + CH(t[3], s[4], s[5]) + k[1] + w[1];
  t[2]  = s[2] + t[6];
  t[6] += S0(t[7]) + MJ(t[7], s[0], s[1]);

  t[5]  = s[5] + S1(t[2]) + CH(t[2], t[3], s[4]) + k[2] + w[2];
  t[1]  = s[1] + t[5];
  t[5] += S0(t[6]) + MJ(t[6], t[7], s[0]);

  t[4]  = s[4] + S1(t[1]) + CH(t[1], t[2], t[3]) + k[3] + w[3];
  t[0]  = s[0] + t[4];
  t[4] += S0(t[5]) + MJ(t[5], t[6], t[7]);

  t[3] += S1(t[0]) + CH(t[0], t[1], t[2]) + k[4] + w[4];
  t[7] += t[3];
  t[3] += S0(t[4]) + MJ(t[4], t[5], t[6]);

  t[2] += S1(t[7]) + CH(t[7], t[0], t[1]) + k[5] + w[5];
  t[6] += t[2];
  t[2] += S0(t[3]) + MJ(t[3], t[4], t[5]);

  t[1] += S1(t[6]) + CH(t[6], t[7], t[0]) + k[6] + w[6];
  t[5] += t[1];
  t[1] += S0(t[2]) + MJ(t[2], t[3], t[4]);

  t[0] += S1(t[5]) + CH(t[5], t[6], t[7]) + k[7] + w[7];
  t[4] += t[0];
  t[0] += S0(t[1]) + MJ(t[1], t[2], t[3]);

  for (i = 8; i < 56; i += 8) {
    t[7] += S1(t[4]) + CH(t[4], t[5], t[6]) + k[i + 0] + w[i + 0];
    t[3] += t[7];
    t[7] += S0(t[0]) + MJ(t[0], t[1], t[2]);
    t[6] += S1(t[3]) + CH(t[3], t[4], t[5]) + k[i + 1] + w[i + 1];
    t[2] += t[6];
    t[6] += S0(t[7]) + MJ(t[7], t[0], t[1]);
    t[5] += S1(t[2]) + CH(t[2], t[3], t[4]) + k[i + 2] + w[i + 2];
    t[1] += t[5];
    t[5] += S0(t[6]) + MJ(t[6], t[7], t[0]);
    t[4] += S1(t[1]) + CH(t[1], t[2], t[3]) + k[i + 3] + w[i + 3];
    t[0] += t[4];
    t[4] += S0(t[5]) + MJ(t[5], t[6], t[7]);
    t[3] += S1(t[0]) + CH(t[0], t[1], t[2]) + k[i + 4] + w[i + 4];
    t[7] += t[3];
    t[3] += S0(t[4]) + MJ(t[4], t[5], t[6]);
    t[2] += S1(t[7]) + CH(t[7], t[0], t[1]) + k[i + 5] + w[i + 5];
    t[6] += t[2];
    t[2] += S0(t[3]) + MJ(t[3], t[4], t[5]);
    t[1] += S1(t[6]) + CH(t[6], t[7], t[0]) + k[i + 6] + w[i + 6];
    t[5] += t[1];
    t[1] += S0(t[2]) + MJ(t[2], t[3], t[4]);
    t[0] += S1(t[5]) + CH(t[5], t[6], t[7]) + k[i + 7] + w[i + 7];
    t[4] += t[0];
    t[0] += S0(t[1]) + MJ(t[1], t[2], t[3]);
  }

  t[7] += S1(t[4]) + CH(t[4], t[5], t[6]) + k[56] + w[56];
  t[3] += t[7];
  t[7] += S0(t[0]) + MJ(t[0], t[1], t[2]);

  t[6] += S1(t[3]) + CH(t[3], t[4], t[5]) + k[57] + w[57];
  t[2] += t[6];
  t[6] += S0(t[7]) + MJ(t[7], t[0], t[1]);

  t[5] += S1(t[2]) + CH(t[2], t[3], t[4]) + k[58] + w[58];
  t[1] += t[5];
  t[5] += S0(t[6]) + MJ(t[6], t[7], t[0]);

  t[4] += S1(t[1]) + CH(t[1], t[2], t[3]) + k[59] + w[59];
  t[0] += t[4];
  t[4] += S0(t[5]) + MJ(t[5], t[6], t[7]);

  t[3] += S1(t[0]) + CH(t[0], t[1], t[2]) + k[60] + w[60];
  t[7] += t[3];
  s[7] += t[7];
  t[3] += S0(t[4]) + MJ(t[4], t[5], t[6]);
  s[3] += t[3];

  t[2] += S1(t[7]) + CH(t[7], t[0], t[1]) + k[61] + w[61];
  t[6] += t[2];
  s[6] += t[6];
  t[2] += S0(t[3]) + MJ(t[3], t[4], t[5]);
  s[2] += t[2];

  t[1] += S1(t[6]) + CH(t[6], t[7], t[0]) + k[62] + w[62];
  t[5] += t[1];
  s[5] += t[5];
  t[1] += S0(t[2]) + MJ(t[2], t[3], t[4]);
  s[1] += t[1];

  t[0] += S1(t[5]) + CH(t[5], t[6], t[7]) + k[63] + w[63];
  s[4] += t[4] + t[0];
  s[0] += t[0] + S0(t[1]) + MJ(t[1], t[2], t[3]);

#endif
}

void
sha256update(
  sha256_t *v
 ,unsigned char *d
 ,unsigned int l
){
  unsigned char *s;

  if (v->l) {
    unsigned int i;

    for (i = v->l, s = v->d + i; l && i < 64; --l, ++i, ++s, ++d)
      *s = *d;
    if (i == 64) {
      sha256mix(v->s, v->d);
      if ((v->bl += 64) < 64)
        ++v->bh;
      v->l = 0;
    } else {
      v->l = i;
      return;
    }
  }
  for (; l >= 64; l -= 64, d += 64) {
    sha256mix(v->s, d);
    if ((v->bl += 64) < 64)
      ++v->bh;
  }
  if (l) {
    v->l = l;
    for (s = v->d; l; --l, ++s, ++d)
      *s = *d;
  }
}

void
sha256final(
  sha256_t *v
 ,unsigned char *h
){
  unsigned char *s;
  unsigned int i;

  if ((i = v->l))
    if ((v->bl += i) < i)
      ++v->bh;
  s = v->d + i++;
  *s++ = 0x80;
  if (i > 64 - 8) {
    for (; i < 64; ++i, ++s)
      *s = 0x00;
    sha256mix(v->s, v->d);
    i = 0;
    s = v->d;
  }
  for (; i < 64 - 8; ++i, ++s)
    *s = 0x00;
  /* convert bytes to bits * 8=2^3 */
  *s++ = v->bh >> (3 * 8 - 3);
  *s++ = v->bh >> (2 * 8 - 3);
  *s++ = v->bh >> (1 * 8 - 3);
  *s++ = v->bh << 3;
  *s++ = v->bl >> (3 * 8 - 3);
  *s++ = v->bl >> (2 * 8 - 3);
  *s++ = v->bl >> (1 * 8 - 3);
  *s   = v->bl << 3;
  sha256mix(v->s, v->d);
  for (i = 0; i < 8; ++i) {
    *h++ = v->s[i] >> (3 * 8);
    *h++ = v->s[i] >> (2 * 8);
    *h++ = v->s[i] >> (1 * 8);
    *h++ = v->s[i] >> (0 * 8);
  }
}

void
sha256hex(
  unsigned char *h
 ,char *o
){
  unsigned int i;

  for (i = 0; i < 32; ++i, ++h) {
    static char m[] = "0123456789abcdef";

    *o++ = m[(*h >> 4) & 0xf];
    *o++ = m[(*h >> 0) & 0xf];
  }
}
