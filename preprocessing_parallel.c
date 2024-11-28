#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>     // For inet_ntop
#include <net/ethernet.h>  // For Ethernet header
#include <netinet/ip.h>    // For IP header
#include <netinet/tcp.h>   // For TCP header
#include <netinet/udp.h>   // For UDP header
#include <omp.h>
#include <mpi.h>

#define MAX_PACKETS 100000
#define OUTPUT_FILE "live_features.csv"

// Define the mapping for protocol encoding
int encode_protocol(const char *protocol_str) {
    if (strcmp(protocol_str, "TCP") == 0) {
        return 0;
    } else if (strcmp(protocol_str, "UDP") == 0) {
        return 1;
    } else if (strcmp(protocol_str, "Non-IP") == 0) {
        return 2;
    } else {
        return 3; // Other protocols
    }
}

typedef struct {
    char time[64];
    int protocol; // Encoded as integer
    int length;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int src_port;
    int dst_port;
    int syn_flag;
    int ack_flag;
    int rst_flag;
    int fin_flag;
} PacketFeature;

void process_packet(const struct pcap_pkthdr *header, const u_char *data, PacketFeature *packet) {
    memset(packet, 0, sizeof(PacketFeature));

    // Get timestamp
    struct tm *ltime;
    char timestr[64];
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    if (ltime) {
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", ltime);
        snprintf(packet->time, sizeof(packet->time), "%s", timestr);
    } else {
        snprintf(packet->time, sizeof(packet->time), "Invalid Time");
    }

    const struct ether_header *eth_header = (struct ether_header *)data;

    // Check if it's an IP packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Parse IP header
        const struct ip *ip_header = (struct ip *)(data + sizeof(struct ether_header));

        inet_ntop(AF_INET, &(ip_header->ip_src), packet->src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), packet->dst_ip, INET_ADDRSTRLEN);

        // Get protocol
        packet->src_port = 0;
        packet->dst_port = 0;

        int ip_header_length = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *)(data + sizeof(struct ether_header) + ip_header_length);

            packet->protocol = encode_protocol("TCP");
            packet->src_port = ntohs(tcp_header->th_sport);
            packet->dst_port = ntohs(tcp_header->th_dport);

            packet->syn_flag = (tcp_header->th_flags & TH_SYN) ? 1 : 0;
            packet->ack_flag = (tcp_header->th_flags & TH_ACK) ? 1 : 0;
            packet->rst_flag = (tcp_header->th_flags & TH_RST) ? 1 : 0;
            packet->fin_flag = (tcp_header->th_flags & TH_FIN) ? 1 : 0;

        } else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *)(data + sizeof(struct ether_header) + ip_header_length);

            packet->protocol = encode_protocol("UDP");
            packet->src_port = ntohs(udp_header->uh_sport);
            packet->dst_port = ntohs(udp_header->uh_dport);

            packet->syn_flag = 0;
            packet->ack_flag = 0;
            packet->rst_flag = 0;
            packet->fin_flag = 0;

        } else {
            packet->protocol = encode_protocol("Other");
        }

        packet->length = header->len;

    } else {
        // Not an IP packet
        packet->protocol = encode_protocol("Non-IP");
        packet->length = header->len;
        packet->src_ip[0] = '\0';
        packet->dst_ip[0] = '\0';
        packet->src_port = 0;
        packet->dst_port = 0;
        packet->syn_flag = 0;
        packet->ack_flag = 0;
        packet->rst_flag = 0;
        packet->fin_flag = 0;
    }
}

void write_to_csv(PacketFeature *packets, int count) {
    FILE *file = fopen(OUTPUT_FILE, "w");
    if (!file) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    // Write CSV header
    fprintf(file, "time,protocol,length,src_ip,dst_ip,src_port,dst_port,syn_flag,ack_flag,rst_flag,fin_flag\n");
    for (int i = 0; i < count; i++) {
        fprintf(file, "%s,%d,%d,%s,%s,%d,%d,%d,%d,%d,%d\n",
                packets[i].time,
                packets[i].protocol,
                packets[i].length,
                packets[i].src_ip[0] != '\0' ? packets[i].src_ip : "",
                packets[i].dst_ip[0] != '\0' ? packets[i].dst_ip : "",
                packets[i].src_port,
                packets[i].dst_port,
                packets[i].syn_flag,
                packets[i].ack_flag,
                packets[i].rst_flag,
                packets[i].fin_flag);
    }
    fclose(file);
    printf("Processed packets written to %s\n", OUTPUT_FILE);
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    if (argc < 2) {
        if (rank == 0) {
            fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        }
        MPI_Finalize();
        exit(EXIT_FAILURE);
    }

    char *pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        if (rank == 0) {
            fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        }
        MPI_Finalize();
        exit(EXIT_FAILURE);
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int packet_count = 0;

    // Allocate memory for PacketFeature array
    PacketFeature *packets = (PacketFeature *)malloc(MAX_PACKETS * sizeof(PacketFeature));
    if (!packets) {
        perror("Error allocating memory for packets");
        MPI_Finalize();
        exit(EXIT_FAILURE);
    }

    int local_packet_count = 0;
    #pragma omp parallel private(header, data)
    {
        while (packet_count < MAX_PACKETS && pcap_next_ex(handle, &header, &data) >= 0) {
            #pragma omp critical
            {
                if (packet_count < MAX_PACKETS) {
                    process_packet(header, data, &packets[packet_count]);
                    packet_count++;
                    local_packet_count++;
                }
            }
        }
    }

    // Send local packet count to rank 0
    int total_packet_count = 0;
    MPI_Reduce(&local_packet_count, &total_packet_count, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    // Send all packets to rank 0
    if (rank == 0) {
        PacketFeature *all_packets = (PacketFeature *)malloc(total_packet_count * sizeof(PacketFeature));
        if (!all_packets) {
            perror("Error allocating memory for all packets");
            MPI_Finalize();
            exit(EXIT_FAILURE);
        }

        MPI_Request *requests = (MPI_Request *)malloc(2 * (size - 1) * sizeof(MPI_Request));
        MPI_Status *statuses = (MPI_Status *)malloc(2 * (size - 1) * sizeof(MPI_Status));
        int offset = 0;
        memcpy(all_packets, packets, local_packet_count * sizeof(PacketFeature));
        offset += local_packet_count;

        for (int i = 1; i < size; i++) {
            int recv_count;
            MPI_Irecv(&recv_count, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &requests[2 * (i - 1)]);
            MPI_Irecv(all_packets + offset, MAX_PACKETS * sizeof(PacketFeature), MPI_BYTE, i, 1, MPI_COMM_WORLD, &requests[2 * (i - 1) + 1]);
            offset += recv_count;
        }

        MPI_Waitall(2 * (size - 1), requests, statuses);

        write_to_csv(all_packets, total_packet_count);
        free(all_packets);
        free(requests);
        free(statuses);
    } else {
        MPI_Request requests[2];
        MPI_Isend(&local_packet_count, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &requests[0]);
        MPI_Isend(packets, local_packet_count * sizeof(PacketFeature), MPI_BYTE, 0, 1, MPI_COMM_WORLD, &requests[1]);
        MPI_Waitall(2, requests, MPI_STATUSES_IGNORE);
    }

    free(packets);
    pcap_close(handle);
    MPI_Finalize();

    return 0;
}