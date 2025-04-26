#pragma once
#include <stdio.h>  
#include <vector>
#include <string>
#include <cstdint>
#include <arpa/inet.h>


class Packet{
    public:
        enum Type: uint8_t {
            HELLO = 0x01,
            OK = 0x02,
            DATA = 0x03,
            WELCOME = 0x04,
            KEY_EXCHANGE = 0x05,
            KEY_EXCHANGE_RESPONSE = 0x06,
            READY = 0x07,
        };

        Packet(Type type, std::vector<uint8_t> payload);
        std::vector<uint8_t> to_bytes() const;
        static Packet from_buffer(const std::vector<uint8_t>& buffer);
        static Packet from_bytes(const std::vector<uint8_t>& buffer);
        Type type() const { return type_; }
        const std::vector<uint8_t>& payload() const { return payload_; }
    
    private:
        Type type_;
        std::vector<uint8_t> payload_;
        
        
        
        
        // uint8_t type;
        // std::vector<uint8_t> data;


        
};