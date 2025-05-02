#pragma once

#include <unordered_map>
#include <tuple>
#include <string>
#include <memory>
#include "network/tcp_session.h"
#include <functional> // for std::hash
#include "network/connectionTupleHash.h"

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

    bool session_exists_for(const std::string& src_ip, const std::string& dst_ip , uint16_t src_port, uint16_t dst_port) const;


private:
    std::unordered_map<SessionKey, std::shared_ptr<TcpSession>, ConnectionTupleHash> sessions_;
};
