#include "network/server.h"

#include <iostream>
static TunHandler* global_tun_handler = nullptr; // global pointer
void handle_sigint(int sig) {
    std::cout << "\n[VPN] Ctrl+C detected! Cleaning up..." << std::endl;
    if (global_tun_handler != nullptr) {
        global_tun_handler->remove_route_for_domain(global_tun_handler->get_io_context(), "example.com", global_tun_handler->get_tun_interface());
    }
    exit(0); // clean exit
}
Server::Server(boost::asio::io_context& io_context, boost::asio::io_context& tun_io_context, short port ): acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), connection_id_(0)
    {
        // do_accept(tun_io_context);
        tun_handler_ = std::make_shared<TunHandler>(tun_io_context, "utun8");
        global_tun_handler = tun_handler_.get(); // set global pointer
        signal(SIGINT, handle_sigint); // <- this line hooks Ctrl+C!


        tun_handler_->start();
        do_accept(tun_io_context);

    }



void Server::do_accept(boost::asio::io_context& tun_io_context) {
    std::cout << "We dont use this anyway" << std::endl;

    acceptor_.async_accept(
                [this, &tun_io_context](boost::system::error_code ec, tcp::socket socket_){
                    if (!ec) {
                        int id = connection_id_++;
                        std::cout << "Accepted connection with id: " << id << std::endl;
                        // auto tun_handler = std::make_shared<TunHandler>(tun_io_context, "utun8");
                        // auto session = std::make_shared<Session>(std::move(socket_), id, Session::INITIAL);
                        auto session = std::make_shared<Session>(tun_io_context, id, Session::SYSTEM);

                        session->set_tun_handler(tun_handler_);
                        tun_handler_->set_session(session);
                        session->start();
                    }
                    do_accept(tun_io_context); // accept the next connection
                }
            );

        }
