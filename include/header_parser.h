#ifndef HEADER_PARSER
#define HEADER_PARSER

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define HEADER_LENGTH (24)

typedef struct {
    bool sec_micro;
    uint32_t SnapLen;
    uint8_t FCS;
    int16_t LinkType;

}header_data;

int is_header_valid(FILE*, header_data*);

#endif