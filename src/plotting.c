#include "plotting.h"

int generate_throughput_chart(const char *output_png, const double *times, const double *kbps, size_t count) {
    if (count == 0) return -1;

    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Gnuplot couldnt be started");
        return -1;
    }

    fprintf(gp, "set terminal pngcairo size 900,500 enhanced font 'Sans,11'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Przepustowosc ruchu sieciowego w czasie'\n");
    fprintf(gp, "set xlabel 'Czas od poczatku przechwytywania [s]'\n");
    fprintf(gp, "set ylabel 'Przepustowosc [KB/s]'\n");
    fprintf(gp, "set grid xtics ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "plot '-' using 1:2 with linespoints lw 2 pt 7 ps 0.7 lc rgb '#1f77b4' title 'Throughput'\n");

    for (size_t i = 0; i < count; i++) {
        fprintf(gp, "%.6f %.2f\n", times[i], kbps[i]);
    }
    fprintf(gp, "e\n");

    return (pclose(gp) == 0) ? 0 : -1;
}

int generate_protocol_type_chart(const char *output_png, uint32_t tcp_pkts, uint32_t udp_pkts, uint32_t other_pkts){
    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Gnuplot couldnt be started");
        return -1;
    }

    uint64_t all_packs = tcp_pkts + udp_pkts + other_pkts;

    fprintf(gp, "set terminal pngcairo size 700,500 enhanced font 'Sans,11'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title \"Analiza ruchu sieciowego\\n{/*0.8 TCP: %.1f%%, UDP: %.1f%%, Other: %.1f%%}\"\n", (double)tcp_pkts/all_packs*100, (double)udp_pkts/all_packs*100, (double)other_pkts/all_packs*100);
    fprintf(gp, "set ylabel 'Liczba pakietow'\n");
    fprintf(gp, "set style fill solid 0.8 border -1\n");
    fprintf(gp, "set boxwidth 0.5\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set grid ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "unset key\n");

    fprintf(gp, "plot '-' using 0:2:xtic(1) with boxes lc rgb '#2ca02c'\n");
    fprintf(gp, "TCP %u\n", tcp_pkts);
    fprintf(gp, "UDP %u\n", udp_pkts);
    fprintf(gp, "Inne %u\n", other_pkts);
    fprintf(gp, "e\n");

    int status = pclose(gp);
    return (status == 0) ? 0 : -1;
}

int generate_size_chart(const char* output_png, uint32_t sz1, uint32_t sz2, uint32_t sz3, uint32_t sz4, uint32_t sz5, uint32_t sz6){
    
    FILE *gp = popen("gnuplot", "w");
    if (gp == NULL) {
        perror("Gnuplot couldnt be started");
        return -1;
    }

    fprintf(gp, "set terminal pngcairo size 700,500 enhanced font 'Sans,11'\n");
    fprintf(gp, "set output '%s'\n", output_png);
    fprintf(gp, "set title 'Histogram rozmiarów pakietów'\n");
    fprintf(gp, "set ylabel 'Liczba pakietow'\n");
    fprintf(gp, "set style fill solid 0.8 border -1\n");
    fprintf(gp, "set boxwidth 0.5\n");
    fprintf(gp, "set yrange [0:*]\n");
    fprintf(gp, "set grid ytics lw 1 lc rgb '#dddddd'\n");
    fprintf(gp, "unset key\n");

    fprintf(gp, "plot '-' using 0:2:xtic(1) with boxes lc rgb '#2ca02c'\n");
    fprintf(gp, "0-64B %u\n", sz1);
    fprintf(gp, "65-256B %u\n", sz2);
    fprintf(gp, "256-512B %u\n", sz3);
    fprintf(gp, "513-1024B %u\n", sz4);
    fprintf(gp, "1025-1518B %u\n", sz5);
    fprintf(gp, "1518B< %u\n", sz6);
    fprintf(gp, "e\n");

    int status = pclose(gp);
    return (status == 0) ? 0 : -1;
}
