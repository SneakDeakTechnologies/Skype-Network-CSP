// crypto/crypto.h
#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <winsock2.h>

#include <openssl/rsa.h>

#include "./rc4/skype_rc4.h"

#define GET_BYTE(arr, index) (((u8*)(arr))[index])

std::vector<uint8_t> get_rc4_key(
    const std::vector<uint8_t>& seed,
    const uint8_t* iv2,
    size_t iv2_size);

void create_rc4_stream(RC4_context* stream, const std::vector<uint8_t>& key);
std::vector<uint8_t> generate_random_iv();

bool make_md5(
    const uint8_t shared_secret[48],
    uint8_t hash8[8],
    const char* prefix);

bool decrypt_session_key(RSA* g_private_key, const unsigned char* encrypted_session_key, unsigned char* aes_key_out);
void aes_ctr(const unsigned char* key, unsigned char* data, unsigned int len, unsigned int IV, unsigned int IV2, unsigned int IV3, unsigned int IV4);
bool verify_access_token(
    const std::string& token,
    const std::string& xor_key_hex,
    const std::string& token_secret,
    std::string& uuid);
uint32_t crc16(const unsigned char* data, unsigned int len);
