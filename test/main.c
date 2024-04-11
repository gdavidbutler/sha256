#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"

int
main(
  void
){
  sha256_t *c;
  size_t i;
  unsigned char h[32];
  unsigned char b[64];

  if (!(c = malloc(sha256tsize())))
    return (1);
  sha256init(c);
  while ((i = fread(b, 1, sizeof (b), stdin)) == sizeof (b))
    sha256update(c, b, i);
  if (i > 0)
    sha256update(c, b, i);
  sha256final(c, h);
  free(c);
  sha256hex(h, (char *)b);
  printf("%.*s\n", (int)sizeof (b), (char *)b);
  return (0);
}
