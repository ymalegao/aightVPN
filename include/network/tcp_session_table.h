#pragma once

#include <unordered_map>
#include <tuple>
#include <string>
#include <memory>
#include "tcp_session.h"
#include <functional> // for std::hash

namespace std {
template <>
struct hash<std::tuple<std::string, uint16_t, std::string, uint16_t>> {
    std::size_t operator()(const std::tuple<std::string, uint16_t, std::string, uint16_t>& key) const {
        const auto& [src_ip, src_port, dst_ip, dst_port] = key;
        std::size_t h1 = std::hash<std::string>{}(src_ip);
        std::size_t h2 = std::hash<uint16_t>{}(src_port);
        std::size_t h3 = std::hash<std::string>{}(dst_ip);
        std::size_t h4 = std::hash<uint16_t>{}(dst_port);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
    }
};
}

class TcpSessionTable {
public:
    using SessionKey = std::tuple<std::string, uint16_t, std::string, uint16_t>;

    std::shared_ptr<TcpSession> get_session(const std::string& src_ip, uint16_t src_port,
                                            const std::string& dst_ip, uint16_t dst_port);

    std::shared_ptr<TcpSession> create_session(const std::string& src_ip, uint16_t src_port,
                                               const std::string& dst_ip, uint16_t dst_port,
                                               boost::asio::io_context& io_context);

    void remove_session(const std::string& src_ip, uint16_t src_port,
                        const std::string& dst_ip, uint16_t dst_port);

private:
    std::unordered_map<SessionKey, std::shared_ptr<TcpSession>> sessions_;
};
