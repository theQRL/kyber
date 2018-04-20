#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#define _GNU_SOURCE 1

#include <stddef.h>

void randombytes(unsigned char *x, size_t xlen);

#endif
