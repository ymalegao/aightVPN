#include "protocol/packet.hpp"
#include <iostream>
#include <boost/asio.hpp>


Packet::Packet(Type type, std::vector<uint8_t> payload): type_(type), payload_(std::move(payload)) {
    std::cout << "Packet created with type: " << static_cast<int>(type_) << std::endl;

}

std::vector<uint8_t> Packet::to_bytes() const { 
    std::vector<uint8_t> bytes;
    
    uint32_t total_len = static_cast<uint32_t>(1 + payload_.size());
    uint32_t network_len = htonl(total_len);

    const uint8_t* len_ptr = reinterpret_cast<const uint8_t*>(&network_len);
    bytes.insert(bytes.end(), len_ptr, len_ptr + 4);

    bytes.push_back(static_cast<uint8_t>(type_));
    bytes.insert(bytes.end(), payload_.begin(), payload_.end());
    return bytes;
}

Packet Packet::from_bytes(const std::vector<uint8_t>& buffer){
    if (buffer.size() < 1) {
        throw std::runtime_error("Buffer too small to contain packet");
    }

    Type type = static_cast<Type>(buffer[0]);
    std::vector<uint8_t> payload(buffer.begin() + 1, buffer.end());
    std::cout << "[Packet::from_bytes] Parsed type: " << static_cast<int>(type)
              << ", payload size: " << payload.size() << std::endl;
    return Packet(type, payload);
}