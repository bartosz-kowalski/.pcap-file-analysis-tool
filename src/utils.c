#include "utils.h"

double get_packet_time(const packet_data *pkt, bool sec_micro){
    double t = (double)pkt->timestamp_sec;
    t += sec_micro ? ((double)pkt->timestamp_2 / 1e6) : ((double)pkt->timestamp_2 / 1e9);
    return t;
}

/*
static double get_time(const packet_data *pkt, bool sec_micro) {
    return (double)pkt->timestamp_sec + (sec_micro ? pkt->timestamp_2 / 1e6 : pkt->timestamp_2 / 1e9);
}

static int cmp_hosts(const void *a, const void *b) {
    uint64_t ba = ((host_stat_t*)a)->bytes;
    uint64_t bb = ((host_stat_t*)b)->bytes;
    return (bb > ba) - (bb < ba);
}

static int cmp_ports(const void *a, const void *b) {
    uint64_t ba = ((port_stat_t*)a)->bytes;
    uint64_t bb = ((port_stat_t*)b)->bytes;
    return (bb > ba) - (bb < ba);
}

void analyze_traffic(const packet_data *packets, const header_data *hdr, host_stat_t *hosts, port_stat_t *ports, flow_t *flows) {
    hosts = calloc(hdr->packet_no * 2, sizeof(host_stat_t));
    ports = calloc(hdr->packet_no * 2, sizeof(port_stat_t));
    flows      = calloc(hdr->packet_no, sizeof(flow_t));
    uint64_t *up_bytes = calloc(hdr->packet_no, sizeof(uint64_t));
    uint64_t *dn_bytes = calloc(hdr->packet_no, sizeof(uint64_t));

    size_t host_cnt = 0, port_cnt = 0, flow_cnt = 0;
    uint32_t frag_packets = 0;
    double total_iat = 0.0;

    for (uint32_t i = 0; i < hdr->packet_no; i++) {
        const ip_info *info = packets[i].final_data;
        if (!info) continue;

        double t = get_time(&packets[i], hdr->sec_micro);
        uint32_t len = packets[i].original_len;

        if (i > 0) {
            double prev_t = get_time(&packets[i - 1], hdr->sec_micro);
            if (t >= prev_t) total_iat += (t - prev_t);
        }

        if (info->is_fragmented || info->frag_offset > 0) {
            frag_packets++;
        }

        const char *ips[2] = { info->src_ip, info->dest_ip };
        for (int k = 0; k < 2; k++) {
            int found = -1;
            for (size_t j = 0; j < host_cnt; j++) {
                if (strcmp(hosts[j].ip, ips[k]) == 0) { found = (int)j; break; }
            }
            if (found == -1) {
                found = (int)host_cnt++;
                strcpy(hosts[found].ip, ips[k]);
            }
            hosts[found].bytes += len;
            hosts[found].packs++;
        }

        uint16_t prts[2] = { info->src_port, info->dest_port };
        for (int k = 0; k < 2; k++) {
            if (prts[k] == 0) continue;
            int found = -1;
            for (size_t j = 0; j < port_cnt; j++) {
                if (ports[j].port == prts[k] && ports[j].protocol == info->protocol_type) {
                    found = (int)j; break;
                }
            }
            if (found == -1) {
                found = (int)port_cnt++;
                ports[found].port = prts[k];
                ports[found].protocol = info->protocol_type;
            }
            ports[found].bytes += len;
            ports[found].packs++;
        }

        int f_idx = -1;
        bool is_upload = true;

        for (size_t j = 0; j < flow_cnt; j++) {
            if (flows[j].protocol != info->protocol_type) continue;

            if (strcmp(flows[j].src_ip, info->src_ip) == 0 && strcmp(flows[j].dst_ip, info->dest_ip) == 0 &&
                flows[j].src_port == info->src_port && flows[j].dst_port == info->dest_port) {
                f_idx = (int)j;
                is_upload = true;
                break;
            }
            if (strcmp(flows[j].src_ip, info->dest_ip) == 0 && strcmp(flows[j].dst_ip, info->src_ip) == 0 &&
                flows[j].src_port == info->dest_port && flows[j].dst_port == info->src_port) {
                f_idx = (int)j;
                is_upload = false;
                break;
            }
        }

        if (f_idx == -1) {
            f_idx = (int)flow_cnt++;
            strcpy(flows[f_idx].src_ip, info->src_ip);
            strcpy(flows[f_idx].dst_ip, info->dest_ip);
            flows[f_idx].src_port = info->src_port;
            flows[f_idx].dst_port = info->dest_port;
            flows[f_idx].protocol = info->protocol_type;
            flows[f_idx].t_first = t;
            is_upload = true;
        }

        flow_t *f = &flows[f_idx];
        f->t_last = t;
        f->bytes += len;
        f->packs++;

        if (is_upload) up_bytes[f_idx] += len;
        else dn_bytes[f_idx] += len;

        if (info->protocol_type == 6) {
            uint8_t fl = info->tcp_flags;
            if ((fl & TCP_SYN) && !(fl & TCP_ACK)) f->has_syn = true;
            if ((fl & TCP_SYN) && (fl & TCP_ACK))  f->has_syn_ack = true;
            if (!(fl & TCP_SYN) && (fl & TCP_ACK)) f->has_ack = true;
            if (fl & TCP_FIN) f->has_fin = true;
            if (fl & TCP_RST) f->has_rst = true;

            if (is_upload && info->tcp_payload_len > 0) {
                if (f->max_seq > 0 && info->seq_num < f->max_seq) {
                    f->retransmissions++;
                }
                if (info->seq_num > f->max_seq) {
                    f->max_seq = info->seq_num;
                }
            }
        }
    }

    qsort(hosts, host_cnt, sizeof(host_stat_t), cmp_hosts);
    qsort(ports, port_cnt, sizeof(port_stat_t), cmp_ports);

    printf("\n--- TOP 5 HOSTS ---\n");
    for (size_t i = 0; i < (host_cnt < 5 ? host_cnt : 5); i++) {
        printf("%zu. %s -> %lu B (%u pkts)\n", i + 1, hosts[i].ip, hosts[i].bytes, hosts[i].packs);
    }

    printf("\n--- TOP 5 PORTS ---\n");
    for (size_t i = 0; i < (port_cnt < 5 ? port_cnt : 5); i++) {
        printf("%zu. Port %u (proto %u) -> %lu B (%u pkts)\n", i + 1, ports[i].port, ports[i].protocol, ports[i].bytes, ports[i].packs);
    }

    uint32_t established = 0, closed_fin = 0, aborted_rst = 0, failed_syn = 0, total_retrans = 0;

    printf("\n--- SESJE (Liczba: %zu) ---\n", flow_cnt);
    for (size_t i = 0; i < flow_cnt; i++) {
        flow_t *f = &flows[i];
        double dur = f->t_last - f->t_first;
        double ratio = (dn_bytes[i] > 0) ? (double)up_bytes[i] / dn_bytes[i] : (double)up_bytes[i];

        if (f->protocol == 6) {
            if (f->has_syn && f->has_syn_ack && f->has_ack) established++;
            if (f->has_fin) closed_fin++;
            if (f->has_rst) aborted_rst++;
            if (f->has_syn && !f->has_syn_ack) failed_syn++;
            total_retrans += f->retransmissions;
        }

        if (i < 10) {
            printf("Sesja %zu: %s:%u <-> %s:%u | Czas: %.3fs | Up/Down: %lu/%lu B (Ratio: %.2f)\n",
                   i + 1, f->src_ip, f->src_port, f->dst_ip, f->dst_port, dur, up_bytes[i], dn_bytes[i], ratio);
        }
    }

    double avg_iat = (hdr->packet_no > 1) ? total_iat / (hdr->packet_no - 1) : 0.0;

    printf("\n--- PODSUMOWANIE TCP I ANOMALII ---\n");
    printf("Poprawne 3-way handshake: %u\n", established);
    printf("Zakonczone FIN: %u | Zerwane RST: %u\n", closed_fin, aborted_rst);
    printf("Nieudane SYN (bez odpowiedzi): %u\n", failed_syn);
    printf("Sredni Inter-Arrival Time (IAT): %.6f s\n", avg_iat);
    printf("Retransmisje TCP: %u\n", total_retrans);
    printf("Pakiety pofragmentowane (IPv4): %u\n", frag_packets);

    free(hosts);
    free(ports);
    free(flows);
    free(up_bytes);
    free(dn_bytes);
} */
