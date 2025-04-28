#include "network/forwarder.h"
#include <iostream>
#include <stdio.h>
#include <unistd.h>

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

void Forwarder::start_connect(const std::string &ip, uint16_t port, DataCallback callback){
    if (is_connecting_ || is_connected_) {
            std::cout << "[Forwarder] Already connecting or connected, ignoring extra SYN" << std::endl;
            return;
    }
    is_connecting_ = true;


    std::cout << "Connecting to target host: " << ip << ":" << port << std::endl;
    response_callback_ = callback;

    auto self = shared_from_this();
    boost::system::error_code ec;
    boost::asio::ip::address address = boost::asio::ip::make_address(ip, ec);

    if (ec) {
            std::cerr << "[forwarder] Invalid IP address: " << ip << " error: " << ec.message() << std::endl;
            return;
    }
    boost::asio::ip::tcp::endpoint endpoint(address, port);

    forward_socket_.async_connect(endpoint, [self](const boost::system::error_code &ec){
        if (!ec){
            std::cout << "Connected to target host: " << std::endl;
        }else{
            std::cerr << "[forwarder] Error connecting to target host: " << ec.message() << std::endl;
        }
        self->handle_connect(ec);

    });
}

void Forwarder::start_streaming(){

    auto self = shared_from_this();
        forward_socket_.async_read_some(boost::asio::buffer(temp_buffer_),
        [this, self](boost::system::error_code ec, std::size_t bytes_transferred){

            if (!ec && bytes_transferred > 0){
                std::cout << "Received " << bytes_transferred << " bytes from target host" << std::endl;

                std::vector<uint8_t> chunk(temp_buffer_.begin(), temp_buffer_.begin() + bytes_transferred);
                if (response_callback_) {
                    response_callback_(chunk, false);
                }
                start_streaming();
            }else if (ec == boost::asio::error::eof){
                std::cout << "Connection closed by target host" << std::endl;
                if (response_callback_) {
                    response_callback_({}, true);
                }
                forward_socket_.close();
            }else{
                std::cerr << "[forwarder] Error reading from target host: " << ec.message() << std::endl;
                forward_socket_.close();

            }
        }
    );

}

void Forwarder::handle_connect(const boost::system::error_code& ec){
    /*
        This is where forward_socket_ connects to the real server (e.g., Netflix).

        If successful, you now have an open TCP connection.

        Then you call async_write(...) to send the raw decrypted payload.
    */
    is_connecting_ = false;
    if (!ec ){
        std::cout << "connected to host" << std::endl;
        is_connected_ = true;
        for (const auto &payload : pending_payloads_){
            send_data(payload);
        }
        pending_payloads_.clear();
        start_streaming();
    }else{
        std::cerr << "[forwarder] Error connecting to target host: " << ec.message() << std::endl;
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

    boost::asio::async_write(forward_socket_, boost::asio::buffer(data), [self](const boost::system::error_code& ec, std::size_t bytes_transferred){
        self->handle_write(ec);
    });
}




void Forwarder::handle_write(const boost::system::error_code& ec){
    //This is where you write the raw payload to the remote endpoint.

    if (!ec){
        std::cout << "Successfully wrote to target host" << std::endl;
        // Start reading the response from the target host
        start_streaming();
    } else {
        std::cerr << "Error writing to target host: " << ec.message() << std::endl;




    }
}
