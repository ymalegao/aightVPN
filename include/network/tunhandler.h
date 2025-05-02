#pragma once

#include <core/tun_device.h>
#include <boost/asio.hpp>
#include <network/tcp_session.h>
#include <vector>
#include <array>
#include <string>
#include "protocol/packet.hpp"
#include "network/session.h"
#include <csignal>   // For signal()
#include <cstdlib>

class TcpSessionTable;
class TcpSession;
class Session;

class TunHandler : public std::enable_shared_from_this<TunHandler>{
public:
    TunHandler(boost::asio::io_context& io_context, const std::string& device_name);
    void remove_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name, const std::string& tun_interface);

    void start();  // Begin reading from the TUN device

    void send_to_tun(const std::vector<uint8_t>& system_payload);  // Write back to the TUN device
    // void handle_vpn_response(const std::vector<uint8_t>& vpn_payload);
    void set_session(std::shared_ptr<Session> session);
    void handle_incoming_packet(const std::vector<uint8_t>& sys_packet);
    boost::asio::io_context& get_io_context() { return io_context_; }
    std::string get_tun_interface() { return tun_name.name; }
    ~TunHandler();
    private:
    void async_read_from_tun();
    void parse_system_packet(const std::vector<uint8_t>& data);
    std::vector<uint8_t> generate_ack_packet(const std::string& src_ip, uint16_t src_port,const std::string& dst_ip, uint16_t dst_port, std::shared_ptr<TcpSession> session);

    boost::asio::io_context& io_context_;

    TunOpenName tun_name;
    int tun_fd_;
    boost::asio::posix::stream_descriptor tun_stream_;


    std::unique_ptr<TcpSessionTable> session_table_;


    std::string device_name_;
    std::array<uint8_t, 4096> read_buffer_;
    std::function<void(Packet)> on_packet_ready_;
    std::shared_ptr<Session> session_;
    std::shared_ptr<Session> system_session_;
    void add_route_for_domain(boost::asio::io_context& io_context, const std::string& domain_name, const std::string& tun_interface);
    std::vector<uint8_t> syn_ack_generator(const std::vector<uint8_t>& synpacket,std::shared_ptr<TcpSession> );

};
