#ifndef PLOTTING
#define PLOTTING

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "packet_parser.h"

int generate_throughput_chart(const char*, const double *, const double *, size_t);

int generate_protocol_type_chart(const char*, uint32_t, uint32_t, uint32_t);

int generate_size_chart(const char*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#endif