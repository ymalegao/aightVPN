#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include <iostream>
#include <cstddef> // Required for offsetof

// Assuming the compute_checksum function from tunhandler is used or defined similarly
// If it's defined elsewhere, ensure it's accessible here.
// Using the standard checksum implementation for clarity:


static uint16_t compute_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < (length & ~1U); i += 2) {
        sum += (data[i] << 8) + data[i + 1];
    }
    if (length & 1) {
        sum += (data[length - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    std::cout << "Checksum: " << std::hex << sum << std::endl;
    uint16_t reversed = (sum >> 8) | (sum << 8);

    std::cout << "checksum reversed " << std::hex << reversed << std::endl;
    return static_cast<uint16_t>(~reversed);
}

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

std::vector<uint8_t> build_tcp_response(const std::string& src_ip, uint16_t src_port,
                                        const std::string& dst_ip, uint16_t dst_port,
                                        uint32_t seq, uint32_t ack,
                                        const std::vector<uint8_t>& payload) {
    size_t ip_header_size = sizeof(struct ip);
    size_t tcp_header_size = sizeof(struct tcphdr);
    size_t total_size = ip_header_size + tcp_header_size + payload.size();

    std::vector<uint8_t> packet(total_size);

    struct ip* iphdr = reinterpret_cast<struct ip*>(packet.data());
    struct tcphdr* tcphdr = reinterpret_cast<struct tcphdr*>(packet.data() + ip_header_size);

    // Fill IP header
    iphdr->ip_v = 4;
    iphdr->ip_hl = ip_header_size / 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(total_size);
    iphdr->ip_id = htons(rand() % 65535); // Consider a better source of IDs if needed
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 64;
    iphdr->ip_p = IPPROTO_TCP;
    inet_pton(AF_INET, src_ip.c_str(), &(iphdr->ip_src));
    inet_pton(AF_INET, dst_ip.c_str(), &(iphdr->ip_dst));
    iphdr->ip_sum = 0;

    // Use the standard compute_checksum for IP header
    iphdr->ip_sum = compute_checksum(reinterpret_cast<const uint8_t*>(iphdr), ip_header_size);

    // Fill TCP header
    tcphdr->th_sport = htons(src_port);
    tcphdr->th_dport = htons(dst_port);
    tcphdr->th_seq = htonl(seq);
    tcphdr->th_ack = htonl(ack);
    tcphdr->th_off = tcp_header_size / 4;
    tcphdr->th_flags = TH_ACK | TH_PUSH; // Set PSH flag for data packets
    tcphdr->th_win = htons(65535);
    tcphdr->th_sum = 0; // Zero out checksum field in the final packet first
    tcphdr->th_urp = 0;

    // Copy payload
    if (!payload.empty()) {
        std::memcpy(packet.data() + ip_header_size + tcp_header_size, payload.data(), payload.size());
    }

    // Calculate TCP checksum
    pseudo_header pshdr;
    std::memset(&pshdr, 0, sizeof(pshdr));
    inet_pton(AF_INET, src_ip.c_str(), &(pshdr.src_addr));
    inet_pton(AF_INET, dst_ip.c_str(), &(pshdr.dst_addr));
    pshdr.zero = 0;
    pshdr.protocol = IPPROTO_TCP;
    pshdr.tcp_length = htons(tcp_header_size + payload.size());

    // Create buffer for checksum calculation
    size_t checksum_buffer_size = sizeof(pshdr) + tcp_header_size + payload.size();
    std::vector<uint8_t> checksum_data(checksum_buffer_size);

    // Copy pseudo header
    std::memcpy(checksum_data.data(), &pshdr, sizeof(pshdr));

    // Copy TCP header and payload from the final packet buffer
    std::memcpy(checksum_data.data() + sizeof(pshdr), packet.data() + ip_header_size, tcp_header_size + payload.size());

    // *** FIX: Explicitly zero out the checksum field within the checksum_data buffer ***
    // The TCP header starts after the pseudo header in checksum_data.
    // The checksum field is at offsetof(struct tcphdr, th_sum) within the TCP header.
    uint16_t* checksum_field_in_buffer = reinterpret_cast<uint16_t*>(
        checksum_data.data() + sizeof(pshdr) + offsetof(struct tcphdr, th_sum)
    );
    *checksum_field_in_buffer = 0;

    // Calculate checksum using the standard function
    uint16_t tcp_checksum = compute_checksum(checksum_data.data(), checksum_buffer_size);

    // Write the calculated checksum back to the final packet buffer
    tcphdr->th_sum = tcp_checksum;

    return packet;
}
