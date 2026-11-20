#ifndef HEADER_PARSER
#define HEADER_PARSER

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define HEADER_LENGTH (24)

// Macro for checking if header data was read correctly
#define CHECK_READ_HEADER(bytes_read, bytes_expected, file)\
    if ((bytes_read) < (size_t)(bytes_expected)) { \
        if (feof(file)) { \
            printf("Reached EOF! \n"); \
        } else if (ferror(file)) { \
            perror("An error occurred while reading the data"); \
        } \
        return -1; \
    } \

typedef struct {
    bool sec_micro;
    uint32_t SnapLen;
    uint8_t FCS;
    uint16_t LinkType;
    uint32_t packet_no;
}header_data;

int is_header_valid(FILE*, header_data*);

int check_packet_no(FILE*, header_data*);

#endif
