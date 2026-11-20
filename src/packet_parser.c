#include "packet_parser.h"

int parse_packets(FILE* pcap_file, packet_data *data, uint32_t packet_no){

    size_t elements_read;
    uint32_t packet_header_data;
    for(int i = 0; i < packet_no; i++){

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        data[i].timestamp_sec = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        data[i].timestamp_2 = packet_header_data;

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        data[i].captured_len = packet_header_data;
        data[i].data = (uint8_t*)malloc(packet_header_data);

        elements_read = fread(&packet_header_data, 4, 1, pcap_file);
        data[i].original_len = packet_header_data;

        fread(data[i].data, data[i].captured_len, 1, pcap_file);

        if(feof(pcap_file)){
            printf("Reached EOF! \n");
            break;
        }
    }

    return 0;
}
