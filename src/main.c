#include "header_parser.h"
#include <string.h>

int main(int argc, char **argv){

    /*
    The first argument must be the filename
    The second one may be the name of the output file
    The third one may be the image folder name
    Names MUST NOT contain spaces or any special characters
    */

    char *pcap_filename;
    char *output_filename;
    char *image_fodler_name;

    if(argc < 1){
        printf("You must include the name of the .PCAP file!");
        return -1;
    }
    else if(argc > 3){
        printf("Too many names given!");
        return -1;
    }
    else{
        // We have to determine the length of the filename (+1 because of '\0' cahracter)
        // Then allocate memory for a copy and copy it
        size_t pcap_filename_len = strlen(argv[0]) + 1;
        char *pcap_filename = malloc(pcap_filename_len);
        memcpy(pcap_filename, argv[0], pcap_filename_len);

        if(argc == 2){
            size_t output_filename_len = strlen(argv[0]) + 1;
            char *output_filename = malloc(output_filename_len);
            memcpy(output_filename, argv[1], output_filename_len);
        }

        if(argc == 3){
            size_t image_fodler_name_len = strlen(argv[0]) + 1;
            char *image_fodler_name = malloc(image_fodler_name_len);
            memcpy(image_fodler_name, argv[2], image_fodler_name_len);
        }
    }

    FILE *pcap_file;
    pcap_file = fopen(pcap_filename, "rb");
    if(pcap_file == NULL){
        printf("Unable to open the file!");
        return -2;
    }

    header_data pcap_header_data;
    is_header_valid(pcap_file, &pcap_header_data);

    return 0;
}