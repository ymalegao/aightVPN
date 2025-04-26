#pragma once
#include <iostream>
// #include "core.h"
#include <stdio.h>
#include <vector>
#include <string>
#include <atomic>
#include <boost/asio.hpp>
#include <thread>
#include "protocol/packet.hpp"
#include "session.h"
#define MAX_CHUNK_SIZE 256

using boost::asio::ip::tcp;

class Forwarder : public std::enable_shared_from_this<Forwarder> {
    public:
        Forwarder(boost::asio::io_context& io_context);

        using DataCallback = std::function<void(const std::vector<uint8_t>&, bool is_complete)>;

        void start_forwarding(const std::string& target_host, short target_port, const std::vector<uint8_t>& payload, DataCallback callback);

    private:
        void handle_connect(const boost::system::error_code& ec);
        void handle_read(const boost::system::error_code& ec, std::size_t bytes_transferred);
        void handle_write(const boost::system::error_code& ec);
        tcp::socket forward_socket_;
        tcp::resolver resolver_;
        std::vector<uint8_t> outbound_payload_;
        std::vector<uint8_t> inbound_payload_;
        boost::asio::streambuf asio_buffer_;
        std::vector<uint8_t> forwarder_buffer_;
        std::array<uint8_t, 4096> temp_buffer_;  // 4 KB buffer for incoming chunks
        void start_streaming();
        std::function<void()> on_stream_end;
        DataCallback response_callback_;



};
