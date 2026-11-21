# PCAP file analysis tool
This tool is designed to parse a .pcap file and generate a comprehensive report on the network traffic. It is writen specifically for Linux, strictly in the C languge and utilizes only the standard C libraries. 
## Prerequisites
To use the program you must have GCC and gnuplot installed.
## Compilation and usage
To compile the program you need to type
```bash
make clean
make
``` 
inside the terminal, while in the main folder of the application.
To run the program you shuold type:
``` bash
build/program param1 param2 
```
where:
- param1 is the .pcap filename (with the .pcap extension!!!),
- param2 is the output filename (without the .pdf extension)\
Names should not contain neither spaces nor any spacial characters.