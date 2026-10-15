// proto/builder/builder.cpp
#define OPENSSL_API_COMPAT 0x10100000L
#define _CRT_SECURE_NO_WARNINGS

#include <random>
#include <cstring>
#include <cstdio>
#include <vector>

#include <openssl/sha.h>

#include "../../crypto/crypto.h"
#include "../../proto/pack-4142/ext42.h"
#include "../../crypto/rc4/skype_rc4.h"
#include "../../proto/common/common.h"
#include "../../proto/objects/objects.h"
#include "builder.h"

std::vector<uint8_t> build_tcp_pkt1(const std::vector<uint8_t>& send_iv, RC4_context* send_rc4) {
    std::vector<uint8_t> tcp_pkt1(14, 0);

    if (send_iv.size() >= 4) {
        memcpy(tcp_pkt1.data(), send_iv.data(), 4);
    }

    uint8_t init_str[10] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03 };
    memcpy(tcp_pkt1.data() + 4, init_str, 10);

    if (send_rc4) {
        RC4_crypt(tcp_pkt1.data() + 4, 10, send_rc4, false);
    }

    return tcp_pkt1;
}

std::vector<uint8_t> build_new_tcp_pkt1(
    const std::vector<uint8_t>& send_iv,
    RC4_context* send_rc4
) {
    const int n = (rand() % 45) + 14;
    const int total = n + 16;

    std::vector<uint8_t> new_tcp_pkt1(total, 0);

    new_tcp_pkt1[0] = send_iv[0];
    new_tcp_pkt1[1] = send_iv[1];
    new_tcp_pkt1[2] = send_iv[2];
    new_tcp_pkt1[3] = send_iv[3];

    const uint16_t zword = static_cast<uint16_t>(rand());
    new_tcp_pkt1[4] = (zword >> 8) & 0xFF;
    new_tcp_pkt1[5] = zword & 0xFF;

    static const uint8_t MARKER[8] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03 };
    std::memcpy(&new_tcp_pkt1[6], MARKER, 8);

    new_tcp_pkt1[14] = static_cast<uint8_t>((n + 1) * 2 + 1);
    new_tcp_pkt1[15] = 0x03;

    for (int i = 16; i < total; i++)
        new_tcp_pkt1[i] = static_cast<uint8_t>(rand() & 0xFF);

    RC4_crypt(&new_tcp_pkt1[4], 10, send_rc4, true);
    RC4_crypt(&new_tcp_pkt1[14], n + 2, send_rc4, false);

    return new_tcp_pkt1;
}

std::vector<uint8_t> build_tcp_pkt2(
    uint16_t seq,
    uint16_t requestID,
    uint32_t stackVersion,
    uint32_t stackTimestamp,
    const struct sockaddr_in& client_addr,
    RC4_context* send_rc4
) {
    std::vector<uint8_t> tcp_pkt2;

    tcp_pkt2.push_back(0x3C);
    tcp_pkt2.push_back((seq >> 8) & 0xFF);
    tcp_pkt2.push_back(seq & 0xFF);

    tcp_pkt2.push_back(0x19);
    tcp_pkt2.push_back(0xFB);
    tcp_pkt2.push_back(0x01);
    tcp_pkt2.push_back((requestID >> 8) & 0xFF);
    tcp_pkt2.push_back(requestID & 0xFF);

    skype_thing things[10];
    int thing_count = 0;

    things[thing_count].type = 0;
    things[thing_count].id = OBJ_ID_STACKVER;
    things[thing_count].m = stackVersion;
    things[thing_count].n = 0;
    thing_count++;

    things[thing_count].type = 0;
    things[thing_count].id = OBJ_ID_STACKTS;
    things[thing_count].m = stackTimestamp;
    things[thing_count].n = 0;
    thing_count++;

    uint16_t client_port = ntohs(client_addr.sin_port);
    things[thing_count].type = 0;
    things[thing_count].id = OBJ_ID_PEERLPORT;
    things[thing_count].m = client_port;
    things[thing_count].n = 0;
    thing_count++;

    uint32_t client_ip = _byteswap_ulong(client_addr.sin_addr.s_addr);
    uint16_t client_port_le = _byteswap_ushort(client_addr.sin_port);

    things[thing_count].type = 2;
    things[thing_count].id = OBJ_ID_PUBNETADDR;
    things[thing_count].m = client_ip;
    things[thing_count].n = client_port_le;
    thing_count++;

    static uint32_t special_data[2] = { 0, 0 };

    things[thing_count].type = 6;
    things[thing_count].id = OBJ_ID_NODE;
    things[thing_count].m = (uint32_t)special_data;
    things[thing_count].n = 8;
    thing_count++;

    uint8_t buffer[4096];
    int packed_size = main_pack(things, thing_count, buffer, sizeof(buffer));

    if (packed_size <= 0) {
        return std::vector<uint8_t>();
    }

    tcp_pkt2.insert(tcp_pkt2.end(), buffer, buffer + packed_size);

    std::vector<uint8_t> encrypted_tcp_pk2_header(3);
    memcpy(encrypted_tcp_pk2_header.data(), tcp_pkt2.data(), 3);
    RC4_crypt(encrypted_tcp_pk2_header.data(), 3, send_rc4, false);

    std::vector<uint8_t> encrypted_tcp_pk2_body(tcp_pkt2.size() - 3);
    memcpy(encrypted_tcp_pk2_body.data(), tcp_pkt2.data() + 3, tcp_pkt2.size() - 3);
    RC4_crypt(encrypted_tcp_pk2_body.data(), encrypted_tcp_pk2_body.size(), send_rc4, false);

    std::vector<uint8_t> encrypted_tcp_pkt2;
    encrypted_tcp_pkt2.reserve(encrypted_tcp_pk2_header.size() + encrypted_tcp_pk2_body.size());
    encrypted_tcp_pkt2.insert(encrypted_tcp_pkt2.end(), encrypted_tcp_pk2_header.begin(), encrypted_tcp_pk2_header.end());
    encrypted_tcp_pkt2.insert(encrypted_tcp_pkt2.end(), encrypted_tcp_pk2_body.begin(), encrypted_tcp_pk2_body.end());

    return encrypted_tcp_pkt2;
}

std::vector<uint8_t> build_tcp_pkt3(
    uint16_t seq,
    uint32_t clients_online,
    RC4_context* send_rc4
) {
    std::vector<uint8_t> tcp_pkt3;

    tcp_pkt3.push_back(0x10);
    tcp_pkt3.push_back((seq >> 8) & 0xFF);
    tcp_pkt3.push_back(seq & 0xFF);

    skype_thing thing{};

    thing.type = 0;
    thing.id = OBJ_ID_NBCONNECTED;
    thing.m = clients_online;
    thing.n = 0;

    uint8_t object_buffer[256];

    int packed_size = main_pack(
        &thing,
        1,
        object_buffer,
        sizeof(object_buffer)
    );

    if (packed_size <= 0) {
        return {};
    }

    tcp_pkt3.push_back(0x04);
    tcp_pkt3.push_back(CMD_NETSTATS);

    tcp_pkt3.insert(
        tcp_pkt3.end(),
        object_buffer,
        object_buffer + packed_size
    );

    std::vector<uint8_t> tcp_pkt3_header(2);
    memcpy(tcp_pkt3_header.data(), tcp_pkt3.data(), 2);
    RC4_crypt(tcp_pkt3_header.data(), 2, send_rc4, false);

    std::vector<uint8_t> tcp_pkt3_body(tcp_pkt3.size() - 2);
    memcpy(tcp_pkt3_body.data(), tcp_pkt3.data() + 2, tcp_pkt3.size() - 2);
    RC4_crypt(tcp_pkt3_body.data(), tcp_pkt3_body.size(), send_rc4, false);

    std::vector<uint8_t> encrypted_tcp_pkt3;
    encrypted_tcp_pkt3.reserve(tcp_pkt3.size());
    encrypted_tcp_pkt3.insert(encrypted_tcp_pkt3.end(), tcp_pkt3_header.begin(), tcp_pkt3_header.end());
    encrypted_tcp_pkt3.insert(encrypted_tcp_pkt3.end(), tcp_pkt3_body.begin(), tcp_pkt3_body.end());

    return encrypted_tcp_pkt3;
}

std::vector<uint8_t> build_tcp_ack(
    uint16_t seq,
    RC4_context* send_rc4
) {
    std::vector<uint8_t> tcp_ack;

    tcp_ack.push_back(0x07);
    tcp_ack.push_back(0x01);
    tcp_ack.push_back((seq >> 8) & 0xFF);
    tcp_ack.push_back(seq & 0xFF);

    std::vector<uint8_t> encrypted_part1(2);
    memcpy(encrypted_part1.data(), tcp_ack.data(), 2);
    RC4_crypt(encrypted_part1.data(), 2, send_rc4, false);

    std::vector<uint8_t> encrypted_part2(2);
    memcpy(encrypted_part2.data(), tcp_ack.data() + 2, 2);
    RC4_crypt(encrypted_part2.data(), 2, send_rc4, false);

    std::vector<uint8_t> encrypted_tcp_ack;
    encrypted_tcp_ack.reserve(encrypted_part1.size() + encrypted_part2.size());
    encrypted_tcp_ack.insert(encrypted_tcp_ack.end(), encrypted_part1.begin(), encrypted_part1.end());
    encrypted_tcp_ack.insert(encrypted_tcp_ack.end(), encrypted_part2.begin(), encrypted_part2.end());

    return encrypted_tcp_ack;
}

int build_auth_answer(unsigned int answerCode, unsigned int seq,
    unsigned char* out, const unsigned char* uic, uint32_t uic_size) {
    int n = 0;

    out[n++] = 0x41;
    out[n++] = 0x03;

    out[n++] = 0x00;
    out[n++] = 0x0A;
    n += write_skype_varint(out + n, answerCode);

    out[n++] = 0x00;
    out[n++] = 0x02;
    out[n++] = seq;

    out[n++] = 0x04;
    out[n++] = 0x24;

    out[n++] = 0x84; 
    out[n++] = 0x02;

    memcpy(out + n, uic, uic_size);
    n += uic_size;

    return n;
}

std::vector<uint8_t> build_aes_packet(
    const unsigned char* aes_key,
    RC4_context* send_rc4,
    unsigned char* body,
    uint32_t body_len
)
{
    aes_ctr(
        aes_key,
        body,
        static_cast<unsigned int>(body_len),
        0x00000001,
        0x00000001,
        0xFFFFFFFF,
        0xFFFF0000
    );

    uint32_t crc_full = crc16(body, body_len);
    uint16_t crc_low = static_cast<uint16_t>(crc_full & 0xFFFF);

    uint16_t payload_len = static_cast<uint16_t>(body_len + 2);

    std::vector<uint8_t> aes_packet;
    aes_packet.reserve(5 + payload_len);

    aes_packet.push_back(0x17);
    aes_packet.push_back(0x03);
    aes_packet.push_back(0x01);
    aes_packet.push_back((payload_len >> 8) & 0xFF);
    aes_packet.push_back(payload_len & 0xFF);
    aes_packet.insert(aes_packet.end(), body, body + body_len);

    aes_packet.push_back(crc_low & 0xFF);
    aes_packet.push_back((crc_low >> 8) & 0xFF);

    RC4_crypt(
        aes_packet.data(),
        aes_packet.size(),
        send_rc4,
        false
    );

    return aes_packet;
}

std::vector<uint8_t> build_auth_response(
    const unsigned char* aes_key,
    RC4_context* send_rc4,
    uint16_t answerCode,
    uint16_t seq,
    const unsigned char* uic,
    uint32_t uic_size
) {
    unsigned char body[512];
    uint32_t body_len = build_auth_answer(answerCode, seq, body, uic, uic_size);

    return build_aes_packet(aes_key, send_rc4, body, body_len);
}

static void append_varuint(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    unsigned char tmp[5];

    const int n = write_skype_varint(
        tmp,
        value
    );

    out.insert(
        out.end(),
        tmp,
        tmp + n
    );
}

static void append_scalar(
    std::vector<unsigned char>& out,
    uint32_t id,
    uint32_t value)
{
    out.push_back(OBJ_FAMILY_NBR);

    const size_t old_size = out.size();
    out.resize(old_size + 5);

    int n = write_skype_varint(
        out.data() + old_size,
        id
    );

    out.resize(old_size + n);

    const size_t value_pos = out.size();
    out.resize(value_pos + 5);

    n = write_skype_varint(
        out.data() + value_pos,
        value
    );

    out.resize(value_pos + n);
}

std::vector<unsigned char> build_uic(
    const char* username,
    const unsigned char* client_modulus,
    uint32_t expiry,
    uint32_t nested_value)
{
    std::vector<unsigned char> uic;

    if (!username || !client_modulus)
        return uic;

    uic.push_back(0x41);
    uic.push_back(0x05);

    uic.push_back(OBJ_FAMILY_STRING);
    append_varuint(uic, OBJ_ID_LDUSER);

    const size_t username_len = std::strlen(username);

    if (username_len == 0 || username_len >= 32)
        return {};

    uic.insert(
        uic.end(),
        reinterpret_cast<const unsigned char*>(username),
        reinterpret_cast<const unsigned char*>(username) + username_len
    );

    uic.push_back(0x00);

    append_scalar(uic, 3, 0);

    uic.push_back(OBJ_FAMILY_BLOB);
    append_varuint(uic, OBJ_ID_LDMODULUS);
    append_varuint(uic, 128);

    uic.insert(
        uic.end(),
        client_modulus,
        client_modulus + 128
    );

    append_scalar(
        uic,
        OBJ_ID_LDEXPIRY,
        expiry
    );

    uic.push_back(OBJ_FAMILY_OBJLIST);
    append_varuint(uic, 2);

    uic.push_back(0x41);
    append_varuint(uic, 1);

    append_scalar(
        uic,
        9,
        nested_value
    );

    return uic;
}

std::vector<unsigned char> finalize_uic(
    RSA* cred_key,
    const std::vector<unsigned char>& payload,
    uint32_t key_descriptor)
{
    if (!cred_key)
        return {};

    const int mod_len = RSA_size(cred_key);

    if (payload.size() + 23 > (size_t)mod_len)
        return {};

    const int bb_count = mod_len - (int)payload.size() - 23;

    std::vector<unsigned char> block;
    block.reserve(mod_len);

    block.push_back(0x4B);
    block.insert(block.end(), bb_count, 0xBB);
    block.push_back(0xBA);
    block.insert(block.end(), payload.begin(), payload.end());

    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1(payload.data(), payload.size(), digest);
    block.insert(block.end(), digest, digest + SHA_DIGEST_LENGTH);

    block.push_back(0xBC);

    std::vector<unsigned char> signature(mod_len);
    const int ret = RSA_private_encrypt(
        mod_len,
        block.data(),
        signature.data(),
        cred_key,
        RSA_NO_PADDING
    );

    if (ret != mod_len)
        return {};

    std::vector<unsigned char> uic;
    uic.reserve(4 + mod_len);
    uic.push_back((unsigned char)((key_descriptor >> 24) & 0xFF));
    uic.push_back((unsigned char)((key_descriptor >> 16) & 0xFF));
    uic.push_back((unsigned char)((key_descriptor >> 8) & 0xFF));
    uic.push_back((unsigned char)(key_descriptor & 0xFF));
    uic.insert(uic.end(), signature.begin(), signature.end());

    return uic;
}
