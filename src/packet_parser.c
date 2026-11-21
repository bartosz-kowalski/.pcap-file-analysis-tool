#include "packet_parser.h"

int strip_ethernet_header(packet_data *pack, const header_data* head) {

    // checking if the frame is adequatly sized
    if (pack->captured_len < (uint32_t)ETHERNET_HEADER_LEN  + head->FCS) {
        return -1; // corrupted frame
    }

    // ether type read
    pack->ether_type = ((uint16_t)pack->raw_data[12] << 8) | pack->raw_data[13];

    // ip header starts at 14th byte
    pack->ip_data = pack->raw_data + ETHERNET_HEADER_LEN;
    pack->info_len = pack->captured_len - ETHERNET_HEADER_LEN - head->FCS;

    return 0;
}

int parse_packets(FILE* pcap_file, packet_data *data, header_data* packet_header){

    size_t elements_read;
    uint32_t packet_header_data;
    uint32_t packet_no = packet_header->packet_no;

    for(uint32_t i = 0; i < packet_no; i++){

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].timestamp_sec = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].timestamp_2 = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].captured_len = packet_header_data;
        data[i].raw_data = (uint8_t*)malloc(packet_header_data);

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        if (elements_read != 1) return -1;
        if(packet_header->endianness == true){
            packet_header_data = __builtin_bswap32(packet_header_data);
        }
        data[i].original_len = packet_header_data;

        elements_read = fread(data[i].raw_data, data[i].captured_len, 1, pcap_file);
        if (elements_read != 1) return -1;

        if(packet_header->LinkType == LINKTYPE_ETHERNET){
            strip_ethernet_header(&data[i], packet_header);
        }
        else if(packet_header->LinkType == LINKTYPE_RAW){
            data[i].ip_data = data[i].raw_data;
            data[i].info_len = data[i].captured_len;
            data[i].ether_type = 0;
        }

    }

    return 0;
}
