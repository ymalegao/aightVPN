#pragma once

#include <vector>
#include <string>
#include <cstdint>

std::vector<uint8_t> build_tcp_response(const std::string& src_ip, uint16_t src_port,
                                        const std::string& dst_ip, uint16_t dst_port,
                                        uint32_t seq, uint32_t ack,
                                        const std::vector<uint8_t>& payload);
