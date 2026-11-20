#ifndef PACKET_PARSER
#define PACKET_PARSER

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct{
    uint32_t timestamp_sec;
    uint32_t timestamp_2;
    uint32_t captured_len;
    uint32_t original_len;
    uint8_t *data;
}packet_data;

int parse_packets(FILE*, packet_data*, uint32_t);

#endif
