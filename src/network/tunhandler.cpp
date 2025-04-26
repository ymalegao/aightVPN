#include <iostream>
#include "network/tunhandler.h"
#include <network/session.h>
#include <string>
#include <sys/socket.h>
#include <iomanip>
#include <cstdlib>  // for std::system
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sstream>  // for building commands


TunHandler::TunHandler(boost::asio::io_context &io_context, const std::string& device_name)
    : io_context_(io_context),
      tun_fd_(tunOpen(&tun_name, device_name.empty() ? nullptr : device_name.c_str())),
      tun_stream_(io_context) {

    if (tun_fd_ < 0) {
        perror("tunOpen failed");  // Show real reason
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
        del_cmd << "sudo route -n delete " << ip_address;

        std::cout << "[VPN][ROUTE] Deleting old route: " << del_cmd.str() << std::endl;
        std::system(del_cmd.str().c_str());

        std::stringstream add_cmd;
        add_cmd << "sudo route -n add -interface " << ip_address << " " << tun_interface;

        std::cout << "[VPN][ROUTE] Adding new route: " << add_cmd.str() << std::endl;
        std::system(add_cmd.str().c_str());

        // break;
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
    if (!TUN_OPEN_IS_IP4(data.data()) && !TUN_OPEN_IS_IP6(data.data())){
        std::cout << "[TUN][PARSE] Not IP4 or IP6, dropping" << std::endl;
        return;
    }
    const uint8_t* ip_packet = data.data() + TUN_OPEN_PACKET_OFFSET;
    // Process IP packet here
    handle_incoming_packet(std::vector<uint8_t>(ip_packet, ip_packet + data.size() - TUN_OPEN_PACKET_OFFSET));
}


void TunHandler::handle_incoming_packet(const std::vector<uint8_t> &sys_packet){
    if (sys_packet.size() < (TUN_OPEN_PACKET_OFFSET + sizeof(struct ip))){
        std::cout << "Invalid packet size" << std::endl;
        return;
    }

    const uint8_t* packet_ptr = sys_packet.data() + TUN_OPEN_PACKET_OFFSET;
    const struct ip* iphdr = reinterpret_cast<const struct ip*>(packet_ptr);

    if (iphdr->ip_v != 4){
        std::cout << "Not IPv4, ignoring" << std::endl;
        return;
    }

    uint16_t ip_len = ntohs(iphdr->ip_len);
    uint8_t proto = iphdr->ip_p;

    if (proto!= IPPROTO_TCP){
        std::cout << "Invalid IP protocol" << std::endl;
        return;
    }

    const struct tcphdr* tcphdr = reinterpret_cast<const struct tcphdr*>(packet_ptr + iphdr->ip_hl * 4);
    uint16_t src_port = ntohs(tcphdr->th_sport);
    uint16_t dst_port = ntohs(tcphdr->th_dport);

    std::cout << "TCP packet received from " << src_port << " to " << dst_port << std::endl;

    // Process the TCP packet further...
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
    std::cout << "Source IP: " << src_ip << std::endl;
    std::cout << "Destination IP: " << dst_ip << std::endl;

    const uint8_t* tcp_payload_ptr = reinterpret_cast<const uint8_t*>(tcphdr) + tcphdr->th_off * 4;
    size_t tcp_payload_length = ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4) - (tcphdr->th_off * 4);

    std::vector<uint8_t> payload_after_headers(tcp_payload_ptr, tcp_payload_ptr + tcp_payload_length);
    if (system_session_){
        Packet packet(Packet::DATA, payload_after_headers);
        system_session_->handle_packet_from_tun(packet, dst_ip, dst_port);
    }
}



void TunHandler::send_to_tun(const std::vector<uint8_t>& system_payload) {
    // Write back to the TUN device
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
        }
    });


}
