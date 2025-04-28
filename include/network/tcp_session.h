#pragma once
#include <memory>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <boost/asio.hpp>
#include "network/forwarder.h"

struct TcpSession {
    enum State {
        SYN_SENT,
        ESTABLISHED,
        FIN_WAIT,
        CLOSED
    };

    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    State state;

    uint32_t client_seq;  // SEQ from the client
    uint32_t client_ack;  // ACK from the client
    uint32_t server_seq;  // SEQ from the server
    uint32_t server_ack;  // ACK from the server

    std::shared_ptr<Forwarder> forwarder;

    TcpSession(const std::string& src_ip, uint16_t src_port,
               const std::string& dst_ip, uint16_t dst_port,
               boost::asio::io_context& io_context)
        : src_ip(src_ip), src_port(src_port), dst_ip(dst_ip), dst_port(dst_port),
          state(SYN_SENT), client_seq(0), client_ack(0), server_seq(0), server_ack(0) {
        forwarder = std::make_shared<Forwarder>(io_context);
    }
};
