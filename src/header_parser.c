#include "header_parser.h"

int is_header_valid(FILE *pcap_file, header_data *data){

    int32_t file_data;
    uint8_t fcs_data;
    uint16_t link_data;
    size_t check;

    // Reading the magic number
    check = fread(&file_data, 4, 1, pcap_file);
    if(check != 1) {
        printf("Unexpected end of file!");
        return -1;
    }
    if(file_data == 0xA1B2C3D4){
        data->sec_micro = true;
    }
    else if(file_data == 0xA1B23C4D){
        data->sec_micro = false;
    }
    else{
        printf("Invalid header! Magic number cannot equal to %d!", file_data);
        return -1;
    }

    // Checking both the minor and major version
    for(int i = 0; i < 2; i++){
        check = fread(&link_data, 2, 1, pcap_file);
        if(check != 1) {
            printf("Unexpected end of file!");
            return -1;
        }
        if(link_data == 2 && i == 0){
            continue;
        }
        else if(link_data == 4 && i == 1){
            continue;
        }
        else{
            printf("Invalid version no.!");
            return -1;
        }
    }

    // Skipping the reserved bits
    for(int i = 0; i < 2; i++){
        check = fread(&file_data, 4, 1, pcap_file);
        if(check != 1) {
            printf("Unexpected end of file!");
            return -1;
        }
        continue;
    }

    // Reading the SnapLen
    check = fread(&file_data, 4, 1, pcap_file);
    if(check != 1) {
        printf("Unexpected end of file!");
        return -1;
    }
    data->SnapLen = file_data;

    // Reading the FCS and skipping unused bits
    check = fread(&fcs_data, 1, 1, pcap_file);
    if(check != 1) {
        printf("Unexpected end of file!");
        return -1;
    }
    bool F = (fcs_data & 16) != 0;

    if(F){
        data->FCS = (fcs_data >> 5  & 7) * 2;
    }
    else{
        data->FCS = 0;
    }

    // Skipiing unused byte
    check = fread(&fcs_data, 1, 1, pcap_file);
    if(check != 1) {
        printf("Unexpected end of file!");
        return -1;
    }

    // Determining the link type
    check = fread(&link_data, 2, 1, pcap_file);
    if(check != 1) {
        printf("Unexpected end of file!");
        return -1;
    }
    data->LinkType = link_data;

    return 0;
}