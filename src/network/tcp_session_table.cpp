#include "network/tcp_session_table.h"



std::shared_ptr<TcpSession> TcpSessionTable::get_session(const std::string& src_ip, uint16_t src_port,
                                                         const std::string& dst_ip, uint16_t dst_port) {
    SessionKey key{src_ip, src_port, dst_ip, dst_port};
    auto it = sessions_.find(key);
    if (it != sessions_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<TcpSession> TcpSessionTable::create_session(const std::string& src_ip, uint16_t src_port,
                                                            const std::string& dst_ip, uint16_t dst_port,
                                                            boost::asio::io_context& io_context) {
    SessionKey key{src_ip, src_port, dst_ip, dst_port};
    auto session = std::make_shared<TcpSession>(src_ip, src_port, dst_ip, dst_port, io_context);
    sessions_[key] = session;
    return session;
}

void TcpSessionTable::remove_session(const std::string& src_ip, uint16_t src_port,
                                     const std::string& dst_ip, uint16_t dst_port) {
    SessionKey key{src_ip, src_port, dst_ip, dst_port};
    sessions_.erase(key);
}
