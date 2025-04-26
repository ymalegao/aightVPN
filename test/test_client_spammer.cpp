#include <boost/asio.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include "protocol/packet.hpp"


using boost::asio::ip::tcp;

void run_client(const std::string& host, int id, short port){
    try {
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        socket.connect(tcp::endpoint(boost::asio::ip::make_address(host), port));
        std::cout << "Client " << id << " connected to server at " << host << ":" << port << std::endl;

        std::string payload = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        Packet data_packet(Packet::DATA, std::vector<uint8_t>(payload.begin(), payload.end()));
        std::vector<uint8_t> data_bytes = data_packet.to_bytes();

        boost::asio::write(socket, boost::asio::buffer(data_bytes));

        std::vector<uint8_t> all_payload;

        while (true) {
            std::array<uint8_t, 4> length_buffer;
            boost::system::error_code ec;

            size_t header_read = boost::asio::read(socket, boost::asio::buffer(length_buffer), ec);
            if (ec) break;

            uint32_t len_net;
            std::memcpy(&len_net, length_buffer.data(), 4);
            uint32_t payload_size = ntohl(len_net);

            std::vector<uint8_t> response(payload_size);
            size_t body_read = boost::asio::read(socket, boost::asio::buffer(response), ec);
            if (ec) break;

            Packet packet = Packet::from_bytes(response);
            std::cout << "Client " << id << " received packet type: " << static_cast<int>(packet.type()) << std::endl;

            const auto& payload = packet.payload();
            all_payload.insert(all_payload.end(), payload.begin(), payload.end());
        }

        std::string full_response(all_payload.begin(), all_payload.end());
        std::cout << "Full response:\n" << full_response << std::endl;
    } catch (std::exception& e){
        std::cerr << "Client error: " << e.what() << std::endl;

    }
}

int main(){
    const int num_clients = 3;
    const std::string host = "127.0.0.1";
    const short port = 12345;
    run_client(host, 0, port);
    // std::vector<std::thread> threads;
    // for (int i = 0; i < num_clients; ++i){
    //     threads.emplace_back(run_client, host, i, port);
    //     std::this_thread::sleep_for(std::chrono::milliseconds(5));
    // }
    // for (auto& thread : threads){
    //     if (thread.joinable()){
    //         thread.join();
    //     }
    // }

    std::cout << "All clients finished." << std::endl;
    return 0;
}
