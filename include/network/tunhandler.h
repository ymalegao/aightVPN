#pragma once

#include <core/tun_device.h>
#include <boost/asio.hpp>
#include <vector>
#include <array>
#include <string>
#include "protocol/packet.hpp"
#include "network/session.h"

class Session;

class TunHandler : public std::enable_shared_from_this<TunHandler>{
public:
    TunHandler(boost::asio::io_context& io_context, const std::string& device_name);
    void start();  // Begin reading from the TUN device
    void send_to_tun(const std::vector<uint8_t>& system_payload);  // Write back to the TUN device
    // void handle_vpn_response(const std::vector<uint8_t>& vpn_payload);
    void set_session(std::shared_ptr<Session> session);
    void handle_incoming_packet(const std::vector<uint8_t>& sys_packet);
    private:
    void async_read_from_tun();
    void parse_system_packet(const std::vector<uint8_t>& data);
    TunOpenName tun_name;

    boost::asio::io_context& io_context_;
    std::string device_name_;
    int tun_fd_;
    boost::asio::posix::stream_descriptor tun_stream_;
    std::array<uint8_t, 4096> read_buffer_;
    std::function<void(Packet)> on_packet_ready_;
    std::shared_ptr<Session> session_;
    std::shared_ptr<Session> system_session_;
    void add_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name, const std::string& tun_interface);




};
