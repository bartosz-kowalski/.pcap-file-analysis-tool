#include "header_parser.h"

#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv){

    /*
    The first argument must be the filename (incl. the extension)
    The second one may be the name of the output file
    The third one may be the image folder name
    Names MUST NOT contain spaces or any special characters
    */

    char *pcap_filename;
    char *output_filename;
    char *image_fodler_name;

    if(argc < 2){
        perror("You must include the name of the .PCAP file! \n");
        return -1;
    }
    else if(argc > 4){
        perror("Too many names given! \n");
        return -1;
    }
    else{
        // We have to determine the length of the filename (+1 because of '\0' cahracter)
        // Then allocate memory for a copy and copy it
        size_t pcap_filename_len = strlen(argv[1]) + 1;
        pcap_filename = (char*)malloc(pcap_filename_len);
        memcpy(pcap_filename, argv[1], pcap_filename_len);

        if(argc == 3){
            size_t output_filename_len = strlen(argv[2]) + 1;
            output_filename = (char*)malloc(output_filename_len);
            memcpy(output_filename, argv[2], output_filename_len);
        }

        if(argc == 4){
            size_t image_fodler_name_len = strlen(argv[3]) + 1;
            image_fodler_name = (char*)malloc(image_fodler_name_len);
            memcpy(image_fodler_name, argv[3], image_fodler_name_len);
        }
    }

    FILE *pcap_file;
    pcap_file = fopen(pcap_filename, "rb");
    if(pcap_file == NULL){
        perror("Unable to open the file! \n");
        return -2;
    }

    header_data pcap_header_data;
    int valid = is_header_valid(pcap_file, &pcap_header_data);
    if(valid != 0){
        printf("ERROR \n");
        return -1;
    }
    printf("Magic number: %d, snaplen: %d, fcs: %d, linktype: %d \n", pcap_header_data.sec_micro, pcap_header_data.SnapLen, pcap_header_data.FCS, pcap_header_data.LinkType);

    check_packet_no(pcap_file, &pcap_header_data);
    printf("Number of packets: %d. \n", pcap_header_data.packet_no);

    free(pcap_filename);
    fclose(pcap_file);

    return 0;
}