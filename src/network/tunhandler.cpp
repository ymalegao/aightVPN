#include <cstdio>
#include <iostream>
#include "network/tunhandler.h"
#include "network/tcp_session_table.h"
#include <network/session.h>
#include <string>
#include <sys/socket.h>
#include <iomanip>
#include <cstdlib>  // for std::system
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sstream>  // for building commands
#include <sys/termios.h>
#include <sys/types.h>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};


#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>


// static uint16_t compute_checksum(const uint8_t* data, size_t length) {
//     uint32_t sum = 0;
//     for (size_t i = 0; i < (length & ~1U); i += 2) {
//         sum += (data[i] << 8) | data[i + 1];
//     }
//     if (length & 1) {
//         sum += (data[length - 1] << 8);
//     }
//     while (sum >> 16) {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }

//     uint16_t result = static_cast<uint16_t>(~sum);
//     return (result >> 8) | (result << 8); // Swap to network byte order
// }


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

TunHandler::TunHandler(boost::asio::io_context &io_context, const std::string& device_name, std::shared_ptr<CryptoManager> crypto_manager)
    : io_context_(io_context),
      tun_fd_(tunOpen(&tun_name, device_name.empty() ? nullptr : device_name.c_str())),
      tun_stream_(io_context),
      session_table_(std::make_unique<TcpSessionTable>()),
      crypto_manager_(crypto_manager) {

    if (tun_fd_ < 0) {
        perror("tunOpen failed");  // Show real     reason
        throw std::runtime_error("Failed to open TUN device");
    }

    int flags = fcntl(tun_fd_, F_GETFL, 0);
    fcntl(tun_fd_, F_SETFL, flags | O_NONBLOCK);
    tun_stream_.assign(tun_fd_);


    std::cout << "Opened TUN device: " << tun_name.name << std::endl;
    std::stringstream cmd;
    cmd << "sudo ifconfig " << tun_name.name << " 10.0.0.1 10.0.0.2 netmask 255.255.255.0 up";
    std::cout << "Running: " << cmd.str() << std::endl;
    int result = std::system(cmd.str().c_str());
    if (result != 0) {
            std::cerr << "ifconfig failed with code " << result << std::endl;
    }



    add_route_for_domain(io_context_, "example.com", tun_name.name);
    // add_route_for_domain(io_context_, "netflix.com", tun_name.name);





}

void TunHandler::add_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name, const std::string& tun_interface) {
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::system::error_code ec;

    auto results = resolver.resolve(domain_name, "", ec);
    if (ec) {
        std::cerr << "[VPN] Failed to resolve domain name: " << domain_name << ", error = " << ec.message() << std::endl;
        return;
    }

    for (auto& entry : results){
        auto endpoint = entry.endpoint();
        auto ip_address = endpoint.address().to_string();

        std::cout << "[VPN][ROUTE] Resolved " << domain_name << " -> " << ip_address << std::endl;

        std::stringstream del_cmd;
        del_cmd << "sudo route delete -host " << ip_address;

        std::cout << "[VPN][ROUTE] Deleting old route: " << del_cmd.str() << std::endl;
        std::system(del_cmd.str().c_str());

        std::stringstream add_cmd;
        add_cmd << "sudo route add -host " << ip_address <<" -interface " <<" " << tun_interface;

        std::cout << "[VPN][ROUTE] Adding new route: " << add_cmd.str() << std::endl;
        std::system(add_cmd.str().c_str());

        // break;
    }

}

void TunHandler::remove_route_for_domain(boost::asio::io_context &io_context, const std::string &domain_name, const std::string &tun_interface){
    boost::asio::ip::tcp::resolver resolver(io_context);
    boost::system::error_code ec;

    auto results = resolver.resolve(domain_name, "", ec);
    if (ec){
        std::cerr << "[VPN][ROUTE] Error resolving domain: " << ec.message() << std::endl;
        return;
    }

    for (auto& entry: results){
        auto endpoint = entry.endpoint();
        auto ip_address = endpoint.address().to_string();

        std::stringstream del_cmd;
        del_cmd << "sudo route -n delete " << ip_address;



        std::cout << "[VPN][CLEANUP] Deleting route for " << ip_address << std::endl;
        std::system(del_cmd.str().c_str());
    }
}



void TunHandler::set_session(std::shared_ptr<Session> session) {
    this->session_ = session;
}

void TunHandler::async_read_from_tun() {


    std::cout << "[TUN] Waiting for system packet..." << std::endl;

    std::cout << "Reading from TUN device..." << std::endl;
    // Reads raw system packet from TUN.
    tun_stream_.async_read_some(boost::asio::buffer(read_buffer_),
                            [this](boost::system::error_code ec, std::size_t length) {
                                std::cout << "[DEBUG] async_read_some fired" << std::endl;

                                if (ec) {
                                                std::cerr << "[TUN] Error in async_read_some: " << ec.message()
                                                          << " (code: " << ec.value() << ")" << std::endl;

                                                // Retry after a short delay
                                                auto timer = std::make_shared<boost::asio::steady_timer>(io_context_,
                                                                                      std::chrono::milliseconds(100));
                                                timer->async_wait([this, timer](const boost::system::error_code&) {
                                                    async_read_from_tun();
                                                });
                                } else {


                                    std::cout << "[TUN] Got packet of size: " << length << std::endl;

                                    std::cout << "[TUN][RAW] Bytes from TUN: ";
                                    for (size_t i = 0; i < length; ++i) {
                                        printf("%02x ", read_buffer_[i]);
                                    }
                                    std::cout << std::endl;

                                    std::string  s(read_buffer_.begin(), read_buffer_.end());
                                    std::cout << s << std::endl;


                                    // Then call parse
                                    std::vector<uint8_t> packet(read_buffer_.begin(), read_buffer_.begin() + length);
                                    parse_system_packet(packet);

                                    // std::vector<uint8_t> packet(read_buffer_.begin(), read_buffer_.end());
                                    // parse_system_packet(packet);




                                    async_read_from_tun();
                                }
                            });
}

void TunHandler::start(){
    std::cout << "[TUN] Starting async_read_from_tun()" << std::endl;
    system_session_ = std::make_shared<Session>(io_context_, 9999, Session::SYSTEM);
    system_session_->start();
    async_read_from_tun();
}

void TunHandler::parse_system_packet(const std::vector<uint8_t>& data) {
    std::cout << "[TUN][PARSE] Got packet of size: " << data.size() << std::endl;


    if (data.size() < TUN_OPEN_PACKET_OFFSET){
        std::cout << "[TUN][PARSE] Packet too small, dropping" << std::endl;
        return;
    };
    uint16_t family = (data[2] << 8) | data[3];

    if (family == AF_INET) {
            std::cout << "[TUN][PARSE] Detected IPv4 packet" << std::endl;
        } else if (family == AF_INET6) {
            std::cout << "[TUN][PARSE] Detected IPv6 packet" << std::endl;
        } else {
            std::cout << "[TUN][PARSE] Unknown family, dropping" << std::endl;
            return;
        }


    const uint8_t* ip_packet = data.data() + TUN_OPEN_PACKET_OFFSET;
    // Process IP packet here
    handle_incoming_packet(std::vector<uint8_t>(ip_packet, ip_packet + data.size() - TUN_OPEN_PACKET_OFFSET));
}


void TunHandler::handle_incoming_packet(const std::vector<uint8_t> &sys_packet) {
    if (sys_packet.size() < (TUN_OPEN_PACKET_OFFSET + sizeof(struct ip))) {
        std::cout << "Invalid packet size" << std::endl;
        return;
    }

    const uint8_t* packet_ptr = sys_packet.data();
    const struct ip* iphdr = reinterpret_cast<const struct ip*>(packet_ptr);

    if (iphdr->ip_v != 4) {
        std::cout << "Not IPv4, ignoring" << std::endl;
        return;
    }

    uint8_t proto = iphdr->ip_p;
    if (proto != IPPROTO_TCP) {
        std::cout << "Invalid IP protocol" << std::endl;
        return;
    }

    const struct tcphdr* tcphdr = reinterpret_cast<const struct tcphdr*>(packet_ptr + iphdr->ip_hl * 4);
    uint8_t flags = tcphdr->th_flags;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    uint16_t src_port = ntohs(tcphdr->th_sport);
    uint16_t dst_port = ntohs(tcphdr->th_dport);

    auto session = session_table_->get_session(src_ip, src_port, dst_ip, dst_port);

    if (!session) {
        // No session exists
        if (flags & TH_SYN) {
            // New incoming SYN
            std::cout << "[TunHandler] New session created" << std::endl;
            session = session_table_->create_session(src_ip, src_port, dst_ip, dst_port, io_context_, crypto_manager_);

            auto syn_ack_packet = syn_ack_generator(sys_packet, session);
            if (!syn_ack_packet.empty()) {
                std::cout << "[TunHandler] Sending SYN-ACK packet" << std::endl;
                send_to_tun(syn_ack_packet);
            }

            session->forwarder->start_connect(dst_ip, dst_port, [this, session](const std::vector<uint8_t>& packet, bool is_complete) {
                std::cout << "[TunHandler] Response callback fired! Data size: " << packet.size() << std::endl;
                if (!packet.empty()) {
                    std::cout << "[TunHandler] Sending packet to tun device" << std::endl;
                    send_to_tun(packet);
                }
                if (is_complete) {
                    std::cout << "[TunHandler] Forwarder closed session" << std::endl;
                    session_table_->remove_session(session->src_ip, session->src_port, session->dst_ip, session->dst_port);
                }
            });

            return;
        } else {
            // No session and not a SYN - DROP
            std::cout << "[TunHandler] No session and not a SYN, dropping packet." << std::endl;
            return;
        }
    } else {
        // Session exists
        if (flags & TH_SYN) {
            // 🚨 Duplicate SYN for existing session, DROP IT
            std::cout << "[TunHandler] Duplicate SYN received for existing session, dropping." << std::endl;
            return;
        }
    }

    // Handle ACK (possibly carrying data)
    if ((flags & TH_ACK) && session->state == TcpSession::SYN_SENT) {
        std::cout << "TCP ACK received. Session established." << std::endl;
        session->state = TcpSession::ESTABLISHED;
        session->client_seq = ntohl(tcphdr->th_seq);
        session->server_seq = ntohl(tcphdr->th_ack);
    }else {
               // Update session state for subsequent ACKs
               uint32_t new_client_seq = ntohl(tcphdr->th_seq);
               uint32_t new_server_ack = ntohl(tcphdr->th_ack);

               std::cout << "TCP ACK update: client SEQ " << session->client_seq
                         << " → " << new_client_seq << ", server ACK "
                         << session->server_seq << " → " << new_server_ack << std::endl;

               // Only update if the new sequence is ahead of the old one
               if (new_client_seq >= session->client_seq) {
                   session->client_seq = new_client_seq;
               }
               if (new_server_ack > session->server_seq) {
                   std::cout << "Server SEQ being updated by client ACK" << std::endl;
                   session->server_seq = new_server_ack;
               }
           }


    const uint8_t* tcp_payload_ptr = reinterpret_cast<const uint8_t*>(tcphdr) + tcphdr->th_off * 4;
    size_t tcp_payload_length = ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4) - (tcphdr->th_off * 4);

    if (tcp_payload_length > 0 && (flags & TH_ACK)) {
        std::vector<uint8_t> payload(tcp_payload_ptr, tcp_payload_ptr + tcp_payload_length);

        // uint32_t original_client_seq = session->client_seq;

        session->client_seq += tcp_payload_length;

        std::cout << "[TunHandler] Forwarding " << payload.size() << " bytes of application data." << std::endl;
        auto encrypted_payload = crypto_manager_->encrypt(sys_packet);
        if (tunnel_callback_) {
          tunnel_callback_(encrypted_payload);
        }


        std::vector<uint8_t> pure_ack = generate_ack_packet(
            session->dst_ip, session->dst_port, session->src_ip, session->src_port, session

        );
        std::cout << "[TunHandler] Generating immediate ACK with SEQ="
                          << session->server_seq << ", ACK=" << session->client_seq << std::endl;

                if (!pure_ack.empty()) {
                    std::cout << "[TunHandler] Sending immediate ACK packet" << std::endl;
                    send_to_tun(pure_ack);
                }
    }

    if (flags & (TH_FIN | TH_RST)) {
        std::cout << "TCP FIN or RST received. Closing session." << std::endl;
        session_table_->remove_session(src_ip, src_port, dst_ip, dst_port);
    }
}

std::vector<uint8_t> TunHandler::generate_ack_packet(const std::string& src_ip, uint16_t src_port,const std::string& dst_ip, uint16_t dst_port, std::shared_ptr<TcpSession> session){
    std::cout << "[TunHandler] Generating ACK packet" << std::endl;
    size_t ip_header_size = sizeof(struct ip);
        size_t tcp_header_size = sizeof(struct tcphdr);
        std::vector<uint8_t> packet(ip_header_size + tcp_header_size);

        // Prepare IP header
        struct ip* iphdr = reinterpret_cast<struct ip*>(packet.data());
        iphdr->ip_v = 4;
        iphdr->ip_hl = ip_header_size / 4;
        iphdr->ip_tos = 0;
        iphdr->ip_len = htons(ip_header_size + tcp_header_size);
        iphdr->ip_id = htons(rand() % 65535);
        iphdr->ip_off = 0;
        iphdr->ip_ttl = 64;
        iphdr->ip_p = IPPROTO_TCP;
        inet_pton(AF_INET, src_ip.c_str(), &(iphdr->ip_src));
        inet_pton(AF_INET, dst_ip.c_str(), &(iphdr->ip_dst));
        iphdr->ip_sum = 0; // Zero before calculating checksum

        // Calculate IP checksum
        iphdr->ip_sum = compute_checksum(packet.data(), ip_header_size);

        // Prepare TCP header
        struct tcphdr* tcphdr = reinterpret_cast<struct tcphdr*>(packet.data() + ip_header_size);
        tcphdr->th_sport = htons(src_port);
        tcphdr->th_dport = htons(dst_port);
        tcphdr->th_seq = htonl(session->server_seq);
        tcphdr->th_ack = htonl(session->client_seq);
        tcphdr->th_off = tcp_header_size / 4;
        tcphdr->th_flags = TH_ACK;  // Pure ACK flag
        tcphdr->th_win = htons(65535);  // Window size
        tcphdr->th_sum = 0;  // Zero before calculating checksum
        tcphdr->th_urp = 0;

        // Calculate TCP checksum
        pseudo_header pshdr{};
        std::memset(&pshdr, 0, sizeof(pshdr));
        inet_pton(AF_INET, src_ip.c_str(), &(pshdr.src_addr));
        inet_pton(AF_INET, dst_ip.c_str(), &(pshdr.dst_addr));
        pshdr.zero = 0;
        pshdr.protocol = IPPROTO_TCP;
        pshdr.tcp_length = htons(tcp_header_size);

        // Create buffer for checksum calculation
        std::vector<uint8_t> checksum_data(sizeof(pshdr) + tcp_header_size);
        std::memcpy(checksum_data.data(), &pshdr, sizeof(pshdr));
        std::memcpy(checksum_data.data() + sizeof(pshdr), packet.data() + ip_header_size, tcp_header_size);

        // Calculate checksum
        uint16_t tcp_checksum = compute_checksum(checksum_data.data(), checksum_data.size());
        tcphdr->th_sum = tcp_checksum;

        return packet;
}

std::vector<uint8_t> TunHandler::syn_ack_generator(const std::vector<uint8_t>& synpacket,std::shared_ptr<TcpSession> session) {
    std::cout << "Generating SYN-ACK packet" << std::endl;

    if (synpacket.size() < sizeof(struct ip) + sizeof(struct tcphdr)) {
        std::cerr << "[syn_ack_generator] Packet too small!" << std::endl;
        return {};
    }

    const struct ip* iphdr_in = reinterpret_cast<const struct ip*>(synpacket.data());
    const struct tcphdr* tcphdr_in = reinterpret_cast<const struct tcphdr*>(synpacket.data() + iphdr_in->ip_hl * 4);

    // size_t tcp_header_size = tcphdr_in->th_off * 4;
    // size_t options_size = tcp_header_size - sizeof(struct tcphdr);
    // const uint8_t* options_ptr = reinterpret_cast<const uint8_t*>(tcphdr_in) + sizeof(struct tcphdr);

    size_t tcp_header_size = sizeof(struct tcphdr);
    // size_t options_size    = 0;
    std::vector<uint8_t> packet(sizeof(struct ip) + tcp_header_size);

    // Prepare IP header
    struct ip iphdr_out{};
    iphdr_out.ip_v = 4;
    iphdr_out.ip_hl = sizeof(struct ip) / 4;
    iphdr_out.ip_tos = iphdr_in->ip_tos;
    iphdr_out.ip_len = htons(sizeof(struct ip) + tcp_header_size);
    iphdr_out.ip_id = htons(rand() % 65535);
    iphdr_out.ip_off = 0;
    iphdr_out.ip_ttl = 64;
    iphdr_out.ip_p = IPPROTO_TCP;
    iphdr_out.ip_src = iphdr_in->ip_dst;
    iphdr_out.ip_dst = iphdr_in->ip_src;
    iphdr_out.ip_sum = 0; // Important: zero before checksum

    // Copy IP header into packet
    std::memcpy(packet.data(), &iphdr_out, sizeof(struct ip));

    // Calculate IP checksum
    uint16_t ip_checksum = compute_checksum(packet.data(), sizeof(struct ip));
    reinterpret_cast<struct ip*>(packet.data())->ip_sum = ip_checksum;

    // Prepare TCP header
    struct tcphdr tcphdr_out{};

    tcphdr_out.th_seq = htonl(session->server_isn);

    tcphdr_out.th_sport = tcphdr_in->th_dport;
    tcphdr_out.th_dport = tcphdr_in->th_sport;
    tcphdr_out.th_ack = htonl(ntohl(tcphdr_in->th_seq) + 1);
    tcphdr_out.th_off = tcp_header_size / 4;
    tcphdr_out.th_flags = TH_SYN | TH_ACK;
    tcphdr_out.th_win = htons(65535);
    tcphdr_out.th_sum = 0; // Important: zero before checksum


    // Copy TCP header
    std::memcpy(packet.data() + sizeof(struct ip), &tcphdr_out, sizeof(struct tcphdr));

    // Copy TCP options
    // if (options_size > 0) {
    //     std::cout << "[SYN-ACK] Copying " << options_size << " bytes of TCP options" << std::endl;
    //     std::memcpy(packet.data() + sizeof(struct ip) + sizeof(struct tcphdr), options_ptr, options_size);
    // }

    // Build pseudo header
    pseudo_header pshdr{};
    pshdr.src_addr = iphdr_out.ip_src.s_addr;
    pshdr.dst_addr = iphdr_out.ip_dst.s_addr;
    pshdr.zero = 0;
    pshdr.protocol = IPPROTO_TCP;
    pshdr.tcp_length = htons(tcp_header_size);


    std::cout << "Pseudo-header:" << std::endl;
    std::cout << "  Source IP: " << inet_ntoa({pshdr.src_addr}) << std::endl;
    std::cout << "  Dest IP: " << inet_ntoa({pshdr.dst_addr}) << std::endl;
    std::cout << "  TCP length: " << ntohs(pshdr.tcp_length) << std::endl;
    std::cout << "  Protocol: " << (int)pshdr.protocol << std::endl;

    std::cout << "TCP header + options:" << std::endl;
    for (size_t i = 0; i < tcp_header_size; ++i) {
        printf("%02x ", packet[sizeof(struct ip) + i]);
    }
    std::cout << std::endl;


    //also dump checksum_data


    std::vector<uint8_t> checksum_data(sizeof(pseudo_header) + tcp_header_size);
    std::memcpy(checksum_data.data(), &pshdr, sizeof(pseudo_header));
    std::memcpy(checksum_data.data() + sizeof(pseudo_header), packet.data() + sizeof(struct ip), tcp_header_size);

    // Zero out checksum field inside checksum_data TCP part
    *(uint16_t*)(checksum_data.data() + sizeof(pseudo_header) + offsetof(struct tcphdr, th_sum)) = 0;

    uint16_t tcp_checksum = compute_checksum(checksum_data.data(), checksum_data.size());
    reinterpret_cast<struct tcphdr*>(packet.data() + sizeof(struct ip))->th_sum = tcp_checksum;

    // std::cout << "Checksum data:" << std::endl;
    // for (size_t i = 0; i < checksum_data.size(); ++i) {
    //     printf("%02x ", checksum_data[i]);
    // }
    // std::coutsession->server_isn = rand();  << std::endl;

    std::cout << "[SYN-ACK] Generated packet of size " << packet.size() << std::endl;
    session->server_seq = session->server_isn + 1;
    session->client_seq = ntohl(tcphdr_in->th_seq) + 1;

    return packet;
}

void TunHandler::send_to_tun(const std::vector<uint8_t>& system_payload) {
    // Write back to the TUN device
    std::cout << "Writing to TUN device..." << std::endl;
    std::cout << "[TunHandler] Sending system_payload of size: " << system_payload.size() << std::endl;

    std::vector<uint8_t> full_packet;

    full_packet.push_back(0x00);
    full_packet.push_back(0x00);
    if (!system_payload.empty() && (system_payload[0] >> 4) == 4 ){
        full_packet.push_back(0x00);
        full_packet.push_back(AF_INET);


    }else{
        full_packet.push_back(0x00);
        full_packet.push_back(AF_INET6);
    }


    full_packet.insert(full_packet.end(), system_payload.begin(), system_payload.end());
    boost::asio::async_write(tun_stream_, boost::asio::buffer(full_packet),
    [](const boost::system::error_code& error, std::size_t bytes_transferred) {
        if (error) {
            // Handle error
            // Log error
            std::cerr << "Failed to write to TUN device" << std::endl;
        }else{
            // Handle success
            // Log success
            std::cout << "Successfully wrote to TUN device" << std::endl;
        }
    });


}

TunHandler::~TunHandler() {
    // Cleanup resources
    // Close TUN device
    // Log cleanup
    std::cout << "TunHandler destroyed" << std::endl;
}
