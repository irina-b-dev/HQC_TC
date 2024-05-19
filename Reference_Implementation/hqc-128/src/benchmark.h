#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>

void benchmark_my_algorithm();
void benchmark_rsa();
void benchmark_dsa();

#endif // BENCHMARK_H