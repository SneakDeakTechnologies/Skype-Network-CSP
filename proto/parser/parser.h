#pragma once

#include <string>
#include <cstddef>
#include <array>

struct tcp_auth_data {
    std::string access_token;
    std::string site_name;
    std::string client_version;
    std::string locale;
    int partner_id = 0;
    std::array<unsigned char, 128> client_modulus{};
    bool has_client_modulus = false;
};

bool parse_tcp_auth(
    const unsigned char* data,
    size_t size,
    tcp_auth_data& out_data
);
