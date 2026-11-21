#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <arpa/inet.h>
#include "packet_parser.h"
#include "header_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

typedef struct{
    char ip[INET6_ADDRSTRLEN]; 
    uint64_t bytes; 
    uint32_t packs;
}host_stat_t;

typedef struct{
    uint16_t port; 
    uint8_t protocol; 
    uint64_t bytes; 
    uint32_t packs;
}port_stat_t;

typedef struct {
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    double t_first;
    double t_last;
    uint64_t bytes;
    uint32_t packs;

    bool has_syn;
    bool has_syn_ack;
    bool has_ack;
    bool has_fin;
    bool has_rst;
    uint32_t max_seq;
    uint32_t retransmissions;

    uint64_t bytes_up;
    uint64_t bytes_down;
} flow_t;

double get_packet_time(const packet_data *, bool);

void analyze_traffic(const packet_data *, const header_data *);

#endif