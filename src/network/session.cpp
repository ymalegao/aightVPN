#include "network/session.h"
#include "network/forwarder.h"
#include <iomanip>
#include <iostream>
#include <stdio.h>
#include <string>
#include <utility>

using namespace std;

Session::Session(boost::asio::io_context& io_context, int id, SessionState state)
    : socket_(io_context), id_(id), state_(state) {
    std::cout << "Session created with id: " << id_ << " and type: " << (state_ == SYSTEM ? "SYSTEM" : "INITIAL") << std::endl;
}

Session::Session(tcp::socket socket, int id, SessionState type)
    : socket_(std::move(socket)), id_(id), state_(type) {
    std::cout << "Session created (TCP) with id: " << id_ << std::endl;
}

void Session::start() {
    if (state_ == SessionState::SYSTEM){
        std::cout << "Starting SYSTEM session with id: " << id_ << std::endl;
        auto& io_context = static_cast<boost::asio::io_context&>(socket_.get_executor().context());

        forwarder_ = std::make_shared<Forwarder>(io_context);


    }else{
        std::cout << "Starting session with id: " << id_ << std::endl;
        auto& io_context = static_cast<boost::asio::io_context&>(socket_.get_executor().context());
        forwarder_ = std::make_shared<Forwarder>(io_context);

        do_read_stream();
    }



}

void Session::set_tun_handler(std::shared_ptr<TunHandler> tun) {
    this->tun_handler = tun;
}

void Session::handle_packet_from_tun(const Packet& packet, const std::string& dst_ip, uint16_t dst_port) {
    forwarder_->start_forwarding(dst_ip, dst_port, packet.payload(),
    [this](const std::vector<uint8_t>& response, bool is_complete){
        std::cout << "Received response from server" << std::endl;
        std::cout << "Response size: " << response.size() << std::endl;
        std::cout << "Sending response to tun" << std::endl;
        tun_handler->send_to_tun(response);
    });
}

void Session::do_read_stream(){
    auto self = shared_from_this();

    std::cout << "Starting read in session " << id_ << std::endl;
    socket_.async_read_some(boost::asio::buffer(temp_buffer_),
        [this,self](boost::system::error_code ec, std::size_t bytes_transferred){
            if (!ec){
                session_buffer_.insert(session_buffer_.end(), temp_buffer_.begin(), temp_buffer_.begin() + bytes_transferred);
                process_buffered_packets();
                do_read_stream(); // Continue reading
            }else{
                std::cerr << "Error reading in session " << id_ << ": " << ec.message() << std::endl;
                socket_.close();
            }
        }
    );
}

void Session::process_buffered_packets(){
    std::cout << "" << "Processing buffered packets in session " << id_ << std::endl;
    while (session_buffer_.size() >= 4){
        uint32_t len_net;
        std::memcpy(&len_net, session_buffer_.data(), 4);
        uint32_t payload_size = ntohl(len_net);
        if (session_buffer_.size() < payload_size + 4){
            std::cout << "Not enough data to process packet in session " << id_ << std::endl;
            break; // Not enough data to process the packet
        }


        std::vector<uint8_t> packet_data(session_buffer_.begin() + 4, session_buffer_.begin() + 4 + payload_size);
        std::cout << "Processing packet of size " << payload_size << " in session " << id_ << std::endl;
        Packet packet = Packet::from_bytes(packet_data);
        std::cout << "Packet type: " << static_cast<int>(packet.type()) << std::endl;
        std::cout << "Packet payload: " << std::string(packet.payload().begin(), packet.payload().end()) << std::endl;
        // Process the packet
        handle_packet(packet, packet_data);
        // Remove the processed packet from the buffer
        session_buffer_.erase(session_buffer_.begin(), session_buffer_.begin() + 4 + payload_size);
    }
}

void Session::do_read(){
    auto self = shared_from_this();
    std::cout << "Starting read in session " << id_ << std::endl;
    //read in chunks


    cout << "Reading length bytes in session " << id_ << std::endl;
    boost::asio::async_read(socket_, boost::asio::buffer(length_buffer_),
        [this, self](boost::system::error_code ec, std::size_t /*length*/){
            if (!ec) {
                std::cout << "[Session " << id_ << "] Raw length bytes: ";
                for (uint8_t byte : length_buffer_) {
                    std::cout << std::hex << static_cast<int>(byte) << " ";
                }
                std::cout << std::dec << std::endl;
                uint32_t len_net;
                std::memcpy(&len_net, length_buffer_.data(), 4);
                uint32_t payload_size = ntohl(len_net);
                if (payload_size > 8192){
                    std::cerr << "rejected invalid payload size: " << payload_size << "in session " <<  id_<<  std::endl;
                    socket_.close();
                    return;
                }
                std::cout << "Received length: " << payload_size << " in session " << id_ << std::endl;

                payload_buffer_.resize(payload_size);


                //now that we read the header of length 4 bytes, we can read the payload
                boost::asio::async_read(socket_, boost::asio::buffer(payload_buffer_),
                    [this, self](boost::system::error_code ec2, std::size_t /*read_len*/){
                        if (!ec2) {
                            // Process the received data
                            Packet packet_ = Packet::from_bytes(payload_buffer_);
                            std::cout << "Packet type: " << static_cast<int>(packet_.type()) << std::endl;
                            std::cout << "Packet payload: " << std::string(packet_.payload().begin(), packet_.payload().end()) << std::endl;
                            // Echo the data back to the client
                            //send welcome message
                            handle_packet(packet_, payload_buffer_);
                        }
                });
            }else{
                std::cerr << "Error reading length in session " << id_ << ": " << ec.message() << std::endl;
                socket_.close();
            }
    });

}

void Session::handle_packet(const Packet& packet, const std::vector<uint8_t>& raw_payload) {
    // Handle the packet based on its type
    std::string debug_payload(packet.payload().begin(), packet.payload().end());
    auto self = shared_from_this();


    switch (packet.type()) {
        case Packet::HELLO:
            std::cout << "Received HELLO packet in session " << id_ << std::endl;
            send_welcome_message();
            break;
        case Packet::KEY_EXCHANGE:
            std::cout << "Received KEY_EXCHANGE packet in session " << id_ << std::endl;
            // Handle key exchange
            break;
        case Packet::DATA:
            std::cout << "Received DATA packet in session " << id_ << std::endl;
            std::cout << "[DEBUG] Payload from DATA packet in session " << id_ << ": \n" << debug_payload << std::endl;
            forwarder_->start_forwarding("example.com", 80, packet.payload(),
            [self](const std::vector<uint8_t>& response_data, bool is_complete) {
                if (!response_data.empty()) {
                    self->do_write(response_data, false);
                }
                if (is_complete) {
                    self->should_close_after_write_ = true;
                    self->flush_write_queue();
                }
            });
            break;
        default:
            std::cerr << "Unknown packet type in session " << id_ << std::endl;
            break;
    }
}

void Session::set_close() {
    socket_.close();
}

void Session::flush_write_queue(){
    auto self = shared_from_this();
    if (!write_queue_.empty() && is_socket_open()) {
        std::vector<uint8_t> bytes = write_queue_.front();
        boost::asio::async_write(socket_, boost::asio::buffer(bytes),
            [this, self](boost::system::error_code ec, std::size_t /*length*/){
                if (!ec) {
                    write_queue_.pop();  // Remove the sent packet from the queue
                    if (write_queue_.empty() && should_close_after_write_){
                        std::cout << "Closing session " << id_ << std::endl;
                        set_close();
                    }else{
                        flush_write_queue(); // Continue sending the next packet
                    }

                } else {
                    std::cerr << "Error writing to socket in session " << id_ << ": " << ec.message() << std::endl;
                    set_close();
                }

        });
    }else if(write_queue_.empty() && should_close_after_write_){
        std::cout << "Closing session " << id_ << std::endl;
        set_close();
    }
}

void Session::do_write(const std::vector<uint8_t>& response_data, bool is_raw) {

    size_t offset = 0;
    while (offset < response_data.size()) {
        size_t chunk_size = std::min(MAX_PACKET_SIZE, response_data.size() - offset);
        std::vector<uint8_t> chunk(response_data.begin() + offset, response_data.begin() + offset + chunk_size);
        Packet packet(Packet::OK, chunk);
        std::vector<uint8_t> bytes = packet.to_bytes();
        write_queue_.push(bytes);  // add to pending writes
        offset += chunk_size;
    }

    flush_write_queue();
}

void Session::send_welcome_message() {
    std::string welcome_message = "Welcome to the server!";
    Packet welcome_packet(Packet::WELCOME, std::vector<uint8_t>(welcome_message.begin(), welcome_message.end()));
    std::vector<uint8_t> welcome_bytes = welcome_packet.to_bytes();
    boost::asio::async_write(socket_, boost::asio::buffer(welcome_bytes),
        [this](boost::system::error_code ec, std::size_t /*length*/){
            if (!ec) {
                std::cout << "Sent welcome message to client in session " << id_ << std::endl;
            }
    });
}
