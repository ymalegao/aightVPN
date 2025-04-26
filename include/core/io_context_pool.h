#pragma once

#include <boost/asio.hpp>
#include <vector>
#include <thread>
#include <iostream>
#include <memory>
#include <atomic>

class IoContextPool {
    public:
        explicit IoContextPool(std::size_t pool_size);
        void run();
        void stop();
        boost::asio::io_context& get_io_context();


    private:
        std::vector<std::shared_ptr<boost::asio::io_context>> io_contexts_;
        std::vector<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guards_;
        std::vector<std::thread> threads_;
        std::atomic<std::size_t> next_;
};