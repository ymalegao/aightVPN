#pragma once
#include <tuple>
#include <string>
#include <cstdint>

struct ConnectionTupleHash {
    std::size_t operator()(const std::tuple<std::string, uint16_t, std::string, uint16_t>& key) const {
        const auto& [src_ip, src_port, dst_ip, dst_port] = key;
        std::size_t h1 = std::hash<std::string>{}(src_ip);
        std::size_t h2 = std::hash<uint16_t>{}(src_port);
        std::size_t h3 = std::hash<std::string>{}(dst_ip);
        std::size_t h4 = std::hash<uint16_t>{}(dst_port);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};
