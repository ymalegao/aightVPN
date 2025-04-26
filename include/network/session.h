#pragma once
#include <boost/asio.hpp>
#include <array>
#include <memory>
#include <thread>
#include "protocol/packet.hpp"
#include <string>
#include <vector>
#include <queue>
#include "network/forwarder.h"
#include "network/tunhandler.h"

#define MAX_PACKET_SIZE size_t(256)
#define CHUNK_SIZE 256


using boost::asio::ip::tcp;
class TunHandler;
class Forwarder;  // forward declaration

class Session : public std::enable_shared_from_this<Session> {



    public:
         enum SessionState {
            INITIAL,
            HELLO,
            OK,
            DATA,
            WELCOME,
            KEY_EXCHANGE,
            KEY_EXCHANGE_RESPONSE,
            READY,
            SYSTEM,
        };
        Session(tcp::socket socket, int id, SessionState state);
        Session(boost::asio::io_context& io_context, int id, SessionState type);

        void start();
        void handle_packet_from_tun(const Packet& packet, const std::string& dst_ip, uint16_t dst_port);
        void set_tun_handler(std::shared_ptr<TunHandler> tun);

    private:
        void do_read();
        void do_read_stream();
        std::shared_ptr<TunHandler> tun_handler;


        void do_write(const std::vector<uint8_t>& response_data, bool is_raw = false);
        void send_welcome_message();
        tcp::socket socket_;
        std::shared_ptr<Forwarder> forwarder_;
        std::array<uint8_t, CHUNK_SIZE> temp_buffer_;


        std::array<uint8_t, 4> length_buffer_;
        std::vector<uint8_t> payload_buffer_;
        void handle_packet(const Packet& packet, const std::vector<uint8_t>& raw_payload);

        int id_;
        SessionState state_;
        std::vector<uint8_t> session_buffer_;
        void process_buffered_packets();
        std::queue<std::vector<uint8_t>> write_queue_;
        void flush_write_queue();
        void set_close();
        bool should_close_after_write_ = false;

        bool is_socket_open() const {
            return socket_.is_open();
        }
};
