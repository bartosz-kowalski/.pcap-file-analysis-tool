#include "header_parser.h"

int is_header_valid(FILE *pcap_file, header_data *data){

    uint32_t file_data;
    uint32_t magic_no_data;
    uint8_t fcs_data;
    uint16_t link_data;
    size_t elements_read;

    // Reading the magic number
    elements_read= fread(&magic_no_data, 4, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    if(magic_no_data == 0xA1B2C3D4){
        data->sec_micro = true;
    }
    else if(magic_no_data== 0xA1B23C4D){
        data->sec_micro = false;
    }
    else{
        perror("Invalid header! Magic number invalid! \n");
        return -1;
    }

    // Checking both the minor and major version
    for(int i = 0; i < 2; i++){
        elements_read = fread(&link_data, 2, 1, pcap_file);
        CHECK_READ_HEADER(elements_read, 1, pcap_file);
        if(link_data == 2 && i == 0){
            continue;
        }
        else if(link_data == 4 && i == 1){
            continue;
        }
        else{
            perror("Invalid version no.! \n");
            return -1;
        }
    }

    // Skipping the reserved bits
    for(int i = 0; i < 2; i++){
        elements_read = fread(&file_data, 4, 1, pcap_file);
        CHECK_READ_HEADER(elements_read, 1, pcap_file);
        continue;
    }

    // Reading the SnapLen
    elements_read = fread(&file_data, 4, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    data->SnapLen = file_data;

    // Reading the FCS and skipping unused bits
    elements_read = fread(&fcs_data, 1, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    bool F = (fcs_data & 16) != 0;

    if(F){
        data->FCS = (fcs_data >> 5  & 7) * 2;
    }
    else{
        data->FCS = 0;
    }

    // Skipiing unused byte
    elements_read = fread(&fcs_data, 1, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);

    // Determining the link type
    elements_read = fread(&link_data, 2, 1, pcap_file);
    CHECK_READ_HEADER(elements_read, 1, pcap_file);
    data->LinkType = link_data;

    printf("Header of the file parsed correctly! \n");

    return 0;
}

int check_packet_no(FILE *pcap_file, header_data *data){

    uint32_t file_data; // timestamps and original packet length
    uint32_t captured_len;
    uint32_t no_packs = 0;
    size_t elements_read;

    while(1){
        // reding the packet timestamp (eof is valid)
        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read == 0 && feof(pcap_file)) {
            printf("Reached the EOF! \n");
            break; 
        }
        if (elements_read != 1) {
            perror("Error occured during reading packet timestamp! \n");
            return -1;
        }

        // readin the rest of the packet header (eof indicates an error)
        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read != 1) {
            perror("Reached an unexpected EOF in the second timestamp! \n");
            return -1;
        }

        elements_read = fread(&captured_len, 4, 1, pcap_file);
        if (elements_read != 1) {
            perror("Reached an unexpected EOF in the captured length! \n");
            return -1;
        }

        elements_read = fread(&file_data, 4, 1, pcap_file);
        if (elements_read != 1){
            perror("Corrupted packet header (missing original packet length)! \n");
            return -1;
        }

        // Skipping packet data and checking EOF
        if (captured_len > 0) {
            if (fseek(pcap_file, captured_len - 1, SEEK_CUR) != 0){
                perror("Failed to skip through the packet data! \n");
                return -1;
            }
            uint8_t buf;
            if (fread(&buf, 1, 1, pcap_file) != 1){
                perror("Unexpected EOF in the packet data! \n");
                return -1;
            }
        }
        
        no_packs += 1;
    }
    
    data->packet_no = no_packs;

    // returning to the start of the file
    if (fseek(pcap_file, 0L, SEEK_SET) != 0){
        perror("Failed to return to the start of the file! \n");
    }

    // skipping the header
    fseek(pcap_file, HEADER_LENGTH, SEEK_CUR);

    return 0;
}
