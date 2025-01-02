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

typedef struct sha256 sha256_t;
unsigned int sha256tsize(void);
void sha256init(sha256_t *);
void sha256update(sha256_t *, const unsigned char *, unsigned int);
void sha256final(sha256_t *, unsigned char *); /* 32 unsigned char (256 bits) */
void sha256hmac(const unsigned char *k, unsigned int kl, const unsigned char *d, unsigned int dl, unsigned char *h); /* 32 unsigned char (256 bits) */
void sha256hex(const unsigned char *, char *); /* 32 unsigned char (256 bits), 64 char (not null-terminated) */
