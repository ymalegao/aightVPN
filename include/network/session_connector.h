#pragma once
#include "network/forwarder.h"
#include "network/tcp_session.h"

// This function connects a session and forwarder
inline void connect_session_and_forwarder(
    std::shared_ptr<TcpSession> session,
    std::shared_ptr<Forwarder> forwarder) {

    session->set_forwarder(forwarder);
    forwarder->set_session(session);
}
