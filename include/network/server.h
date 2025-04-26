#pragma once
#include <iostream>
// #include "core.h"
#include <stdio.h>
#include <vector>
#include <string>
#include <atomic>
#include <boost/asio.hpp>
#include <thread>
#include "protocol/packet.hpp"
#include "session.h"
#include "tunhandler.h"

using boost::asio::ip::tcp;

class Server {
    public:
        Server(boost::asio::io_context& io_context, boost::asio::io_context& tun_io_context,short port );

        void do_accept(boost::asio::io_context& io_context);


    private:
        tcp::acceptor acceptor_;
        std::atomic<int> connection_id_;
        std::shared_ptr<TunHandler> tun_handler_;

};
