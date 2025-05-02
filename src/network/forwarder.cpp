#include "network/forwarder.h"
#include "network/tcp_session.h"

#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <network/tcp_response_builder.h>

Forwarder::Forwarder(boost::asio::io_context& io_context)
    : forward_socket_(io_context), resolver_(io_context) {
    std::cout << "Forwarder created" << std::endl;
}

void Forwarder::start_forwarding(const std::string& target_host, short target_port, const std::vector<uint8_t>& payload, DataCallback callback){
    std::cout << "Starting forwarding to target host: " << target_host << ":" << target_port << std::endl;
    outbound_payload_ = payload;
    std::cout << "outbound payload size: " << outbound_payload_.size() << std::endl;
    response_callback_ = callback;
    std::cout << "Connecting to target host: " << target_host << ":" << target_port << std::endl;





    auto endpoints = resolver_.resolve(target_host, std::to_string(target_port));
    std::cout << "Resolved target host: " << target_host << ":" << target_port << std::endl;
    auto self = shared_from_this();
    boost::asio::async_connect(forward_socket_, endpoints,
        [self](const boost::system::error_code& ec, const tcp::endpoint& endpoint) {
            std::cout << "Connected to target host: " << endpoint.address().to_string() << ":" << endpoint.port() << std::endl;

            if (!ec ){
                std::cout << "Connected to target host: " << endpoint.address().to_string() << ":" << endpoint.port() << std::endl;
            } else {
                std::cerr <<  "[forwarder] Error connecting to target host: " << ec.message() << std::endl;
            }
            self->handle_connect(ec);
        });
}

void Forwarder::set_session(std::shared_ptr<TcpSession> session) {
    session_ = session;
}

void Forwarder::start_connect(const std::string &ip, uint16_t port, DataCallback callback){
    if (forward_socket_.is_open()) {
            std::cout << "[Forwarder] Closing existing socket before new connection" << std::endl;
            boost::system::error_code ec;
            forward_socket_.close(ec);
            is_connected_ = false;

        }

        boost::system::error_code ec;
            forward_socket_.open(boost::asio::ip::tcp::v4(), ec);
            if (ec) {
                std::cerr << "[Forwarder] Failed to open socket: " << ec.message() << std::endl;
                return;
            }

            // NOW set the binding option after the socket is opened
            int en0_idx = if_nametoindex("en0");
            if (en0_idx == 0) {
                perror("if_nametoindex");
            } else {
                int fd = forward_socket_.native_handle();
                if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &en0_idx, sizeof(en0_idx)) < 0) {
                    perror("setsockopt IP_BOUND_IF");
                } else {
                    std::cout << "[Forwarder] Bound socket to en0 (ifindex=" << en0_idx << ")\n";
                }
            }



    if (is_connecting_ || is_connected_) {
            std::cout << "[Forwarder] Already connecting or connected, ignoring extra SYN" << std::endl;
            return;
    }


    std::cout << "Connecting to target host: " << ip << ":" << port << std::endl;
    is_connecting_ = true;
    response_callback_ = callback;

    auto self = shared_from_this();
    boost::asio::ip::address address = boost::asio::ip::make_address(ip, ec);

    if (ec) {
            std::cerr << "[forwarder] Invalid IP address: " << ip << " error: " << ec.message() << std::endl;
            return;
    }
    boost::asio::ip::tcp::endpoint endpoint(address, port);

    std::cout << "[Forwarder] Connecting to " << ip << ":" << port << "..." << std::endl;

    auto timer = std::make_shared<boost::asio::steady_timer>(
            forward_socket_.get_executor(), std::chrono::seconds(5));

        timer->async_wait([self, timer](const boost::system::error_code& ec) {
            if (!ec && self->is_connecting_ && !self->is_connected_) {
                std::cerr << "[Forwarder] Connection attempt timed out" << std::endl;
                self->is_connecting_ = false;
                boost::system::error_code close_ec;
                self->forward_socket_.close(close_ec);
            }
        });

    forward_socket_.async_connect(endpoint, [self, timer](const boost::system::error_code &ec){
        timer->cancel();
        std::cout << "[Forwarder] Timer cancelled" << std::endl;
        self->is_connecting_ = false;


        if (!ec){
            std::cout << "[Forwarder] Successfully connected to target host: "
                            << self->forward_socket_.remote_endpoint() << std::endl;
            self->is_connected_ = true;

            for (const auto& payload: self->pending_payloads_){
                self->send_data(payload);
            }
            self->pending_payloads_.clear();

            self->start_streaming();
        }else{
            std::cerr << "[forwarder] Error connecting to target host: " << ec.message() << std::endl;
        }

    });
}
void Forwarder::start_streaming() {
    std::cout << "[Forwarder] Starting to read from server socket" << std::endl;
    std::cout << "[Forwarder] Socket open: " << forward_socket_.is_open() << std::endl;

    auto self = shared_from_this();
    if (!self) {
        std::cerr << "[Forwarder] Error: self is null" << std::endl;
        return;
    }
    if (!forward_socket_.is_open()) {
        std::cerr << "[Forwarder] Socket is not open, cannot start streaming" << std::endl;
        return;
    }

    forward_socket_.async_read_some(
        boost::asio::buffer(temp_buffer_),
        [this, self](boost::system::error_code ec, std::size_t bytes_transferred) {
            std::cout << "[Forwarder] async_read_some fired"
                      << "  bytes=" << bytes_transferred
                      << "  error=" << (ec ? ec.message() : "none")
                      << std::endl;

            // 1) Connection closed by server → send FIN back into TUN
            if (ec == boost::asio::error::eof) {
                std::cout << "[Forwarder] Connection closed by target host" << std::endl;
                if (response_callback_) {
                    // empty payload + FIN flag
                    response_callback_({}, /*fin=*/true);
                }
                return;
            }
            // 2) Other fatal error → bail out
            if (ec) {
                std::cerr << "[Forwarder] Read error: " << ec.message() << std::endl;
                return;
            }

            // 3) Build the chunk (may be empty for pure ACKs)
            std::vector<uint8_t> chunk;
            if (bytes_transferred > 0) {
                chunk.assign(temp_buffer_.begin(),
                             temp_buffer_.begin() + bytes_transferred);
            }

            // 4) Grab session info
            auto session = session_.lock();
            if (!session) {
                std::cerr << "[Forwarder] Session expired, stopping streamer" << std::endl;
                return;
            }

            // 5) Build TCP response packet (data+ACK or ACK-only)
            auto tcp_response = build_tcp_response(
                /*src_ip=*/ session->dst_ip,
                /*src_port=*/ session->dst_port,
                /*dst_ip=*/ session->src_ip,
                /*dst_port=*/ session->src_port,
                /*seq=*/ session->server_seq,
                /*ack=*/ session->client_seq,
                /*payload=*/ chunk
            );

            // 6) Advance server_seq by payload length
            session->server_seq += chunk.size();

            std::cout << "[Forwarder] Forwarding "
                      << (chunk.empty() ? "ACK-only" : "data+ACK")
                      << " back to client"
                      << "  seq=" << session->server_seq
                      << "  ack=" << session->client_seq
                      << "  payload=" << chunk.size()
                      << std::endl;

            // 7) Send it into the TUN
            if (response_callback_) {
                response_callback_(tcp_response, /*fin=*/false);
            } else {
                std::cerr << "[Forwarder] No response callback set!" << std::endl;
                return;
            }

            // 8) Loop to keep reading forever
            start_streaming();
        }
    );
}


void Forwarder::handle_connect(const boost::system::error_code& ec){
    /*
        This is where forward_socket_ connects to the real server (e.g., Netflix).

        If successful, you now have an open TCP connection.

        Then you call async_write(...) to send the raw decrypted payload.
    */
    std::cout << "[Forwarder] handle_connect() entered" << std::endl;

    is_connecting_ = false;
    if (!ec ){
        std::cout << "[Forwarder] Successfully connected to target host: "
                         << forward_socket_.remote_endpoint() << std::endl;
        is_connected_ = true;

        for (const auto &payload : pending_payloads_){

            send_data(payload);
        }
        std::cout << "forwarder connected" << std::endl;
        pending_payloads_.clear();
        std::cout << "start streaming" << std::endl;
        start_streaming();

    }else{
        std::cerr << "[forwarder] Error connecting to target host: " << ec.message() << std::endl;
        forward_socket_.close();
    }
}

void Forwarder::send_data(const std::vector<uint8_t> &data){
    if (!is_connected_){
        std::cout << "forwarder not connected yet" << std::endl;
        pending_payloads_.push_back(data);
        return;
    }
    auto self = shared_from_this();
    std::cout << "sending data" << std::endl;

    std::cout << "[Forwarder] Dumping payload about to send:" << std::endl;
        for (size_t i = 0; i < std::min(data.size(), size_t(64)); ++i) {
            printf("%02x ", data[i]);
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;

        std::cout << "[Forwarder] Dumping HTTP payload (ASCII):\n";
        for (uint8_t c : data) {
            if (std::isprint(c)) std::cout << (char)c;
            else std::cout << '.';
        }
        std::cout << "\n\n[Forwarder] Dumping raw bytes:\n";
        for (size_t i = 0; i < data.size(); ++i) {
            printf("%02x ", data[i]);
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;

    boost::asio::async_write(forward_socket_, boost::asio::buffer(data),
            [self, data](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                std::cout << "[Forwarder] Sent " << bytes_transferred << "/" << data.size()
                          << " bytes to server. Error: " << ec.message() << std::endl;
                self->handle_write(ec);
            }
        );
}




void Forwarder::handle_write(const boost::system::error_code& ec){
    //This is where you write the raw payload to the remote endpoint.

    if (!ec){
        std::cout << "Successfully wrote to target host" << std::endl;
        // start_streaming();

        // Start reading the response from the target host
    } else {
        std::cerr << "Error writing to target host: " << ec.message() << std::endl;
        forward_socket_.close();
        is_connected_ = false;




    }
}
