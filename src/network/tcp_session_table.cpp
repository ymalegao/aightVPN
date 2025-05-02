#include "network/tcp_session_table.h"
#include "network/forwarder.h"
#include "network/session_connector.h"




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
    session->server_isn = rand();
    session->server_seq = session->server_isn+1;
    auto forwarder = std::make_shared<Forwarder>(io_context);
    connect_session_and_forwarder(session, forwarder);
    sessions_[key] = session;
    return session;
}

void TcpSessionTable::remove_session(const std::string& src_ip, uint16_t src_port,
                                     const std::string& dst_ip, uint16_t dst_port) {
    SessionKey key{src_ip, src_port, dst_ip, dst_port};
    sessions_.erase(key);
}


bool TcpSessionTable::session_exists_for(const std::string& src_ip, const std::string& dst_ip, uint16_t src_port, uint16_t dst_port) const{
    for (const auto& entry: sessions_){
        const auto& tuple = entry.first;
        const auto& t_src_ip = std::get<0>(tuple);
        const auto& t_dst_ip = std::get<2>(tuple);

        const auto& t_src_port = std::get<1>(tuple);
        const auto& t_dst_port = std::get<3>(tuple);


        bool forward_match = (t_src_ip == src_ip && t_dst_ip == dst_ip && t_src_port == src_port && t_dst_port == dst_port);
        bool reverse_match = (t_src_ip == dst_ip && t_dst_ip == src_ip && t_src_port == dst_port && t_dst_port == src_port);

        if (forward_match || reverse_match){
            return true;
        }
    }
    return false;
}
