#ifndef IP_PARSER
#define IP_PARSER

#include "header_parser.h"
#include "packet_parser.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

int parse_ip_packet(packet_data*);

#endif