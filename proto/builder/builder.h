#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <winsock2.h>

#include "../../crypto/rc4/skype_rc4.h"
#include "../../crypto/crypto.h"
#include "../common/common.h"

// TCP
std::vector<uint8_t> build_tcp_pkt1(
    const std::vector<uint8_t>& send_iv,
    RC4_context* send_rc4
);

std::vector<uint8_t> build_new_tcp_pkt1(
    const std::vector<uint8_t>& send_iv,
    RC4_context* send_rc4
);

std::vector<uint8_t> build_tcp_pkt2(
    uint16_t seq,
    uint16_t requestID,
    uint32_t stackVersion,
    uint32_t stackTimestamp,
    const struct sockaddr_in& client_addr,
    RC4_context* send_rc4
);

std::vector<uint8_t> build_tcp_pkt3(
    uint16_t seq,
    uint32_t clients_online,
    RC4_context* send_rc4
);

std::vector<uint8_t> build_tcp_ack(
    uint16_t seq,
    RC4_context* send_rc4
);

std::vector<uint8_t> build_auth_response(
    const unsigned char* aes_key,
    RC4_context* send_rc4,
    uint16_t answerCode,
    uint16_t seq,
    const unsigned char* uic,
    uint32_t uic_size
);

std::vector<unsigned char> build_uic(
    const char* username,
    const unsigned char* client_modulus,
    uint32_t expiry,
    uint32_t nested_value);

std::vector<unsigned char> finalize_uic(
    RSA* cred_key,
    const std::vector<unsigned char>& payload,
    uint32_t key_descriptor);
