#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

/* reads a NIST SHA-256 vector file from standard input and validates the implementation */

int
main(
  void
){
  static unsigned char const t[] = {
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x00-0x0f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x10-0x1f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x20-0x2f */
     0,  1,  2,  3,   4,  5,  6,  7,   8,  9,  0,  0,   0,  0,  0,  0, /* 0x30-0x3f */
     0, 10, 11, 12,  13, 14, 15,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x40-0x4f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x50-0x5f */
     0, 10, 11, 12,  13, 14, 15,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x60-0x6f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x70-0x7f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x80-0x8f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0x90-0x9f */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0xa0-0xaf */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0xb0-0xbf */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0xc0-0xcf */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0xd0-0xdf */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0, /* 0xe0-0xef */
     0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0,   0,  0,  0,  0  /* 0xf0-0xff */
  };
  unsigned char *b;
  sha256_t *s;
  unsigned int l;

  if (!(s = sha256alloc((void *(*)(unsigned int))malloc))
   || !(b = malloc(16384)))
    return (1);
  l = 0;
  while (fgets((char *)b, 16384, stdin)) {
    unsigned char *p;
    unsigned char h[32];
    unsigned char o[64];
    unsigned int i;

    switch (*b) {

    case 'L': /* Len = */
      if ((l = atoi((char *)b + 6)) < 0)
        l = 0;
      else
        l /= 8; /* 8 bits per byte */
      break;

    case 'M':
      switch (*(b + 1)) {

      case 's': /* Msg = */
        sha256init(s);
        p = b + 6;
        for (; l >= sizeof (o); l -= sizeof (o)) {
          for (i = 0; i < sizeof (o); ++i, p += 2)
            o[i] = t[*(p + 0)] << 4 | t[*(p + 1)];
          sha256update(s, o, sizeof (o));
        }
        if (l) {
          for (i = 0; i < l; ++i, p += 2)
            o[i] = t[*(p + 0)] << 4 | t[*(p + 1)];
          sha256update(s, o, i);
        }
        sha256final(s, h);
        break;

      case 'D': /* MD = */
        sha256hex(h, (char *)o);
        if (memcmp(b + 5, o, sizeof (o)))
          printf("%.64s != %.64s\n", o, b + 5);
        break;
      }
      l = 0;
      break;

    case '\r':
    case '[':
    case '#':
      l = 0;
      break;
    }
  }
  free(b);
  free(s);
  return (0);
}
