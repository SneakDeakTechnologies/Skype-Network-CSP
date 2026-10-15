// crypto/crypto.cpp
#define OPENSSL_API_COMPAT 0x10100000L
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include "crypto.h"

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif
#include <cstring>
#include <cstdio>
#include <array>
#include <random>
#include <ctime>

#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <windows.h>
#include <wincrypt.h>

#include "../crypto/sha1/sha1.h"
#include "../crypto/rijndael/rijndael.h"
#include "./rc4/skype_rc4.h"

#pragma comment(lib, "Crypt32.lib")

static inline u32 dword_get(const unsigned char* p) { u32 v; memcpy(&v, p, 4); return v; }
static inline void dword_set(unsigned char* p, u32 v) { memcpy(p, &v, 4); }

static inline u32 bswap32(u32 x)
{
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) |
        ((x & 0xFF0000) >> 8) | ((x >> 24) & 0xFF);
}

std::vector<uint8_t> get_rc4_key(
    const std::vector<uint8_t>& seed,
    const uint8_t* iv2,
    size_t iv2_size
)
{
    constexpr size_t key_size = 80;
    std::vector<uint8_t> full_key(key_size, 0);

    if (seed.size() < 4) {
        return {};
    }

    const uint32_t iv =
        (static_cast<uint32_t>(seed[0]) << 24) |
        (static_cast<uint32_t>(seed[1]) << 16) |
        (static_cast<uint32_t>(seed[2]) << 8) |
        static_cast<uint32_t>(seed[3]);

    Skype_RC4_Get_Expanded_Key(
        iv,
        iv2,
        full_key.data(),
        1,
        iv2_size
    );

    return full_key;
}

void create_rc4_stream(RC4_context* stream, const std::vector<uint8_t>& key) {
    if (!stream) {
        return;
    }

    stream->i = 0;
    stream->j = 0;

    for (int i = 0; i < 256; i++) {
        stream->s[i] = i;
    }

    int j = 0;

    for (int i = 0; i < 256; i++) {
        j = (j + stream->s[i] + key[i % key.size()]) & 0xFF;
        uint8_t tmp = stream->s[i];
        stream->s[i] = stream->s[j];
        stream->s[j] = tmp;
    }
}

std::vector<uint8_t> generate_random_iv() {
    std::vector<uint8_t> iv(4);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);

    uint32_t iv_value = dis(gen);

    iv[0] = (iv_value >> 24) & 0xFF;
    iv[1] = (iv_value >> 16) & 0xFF;
    iv[2] = (iv_value >> 8) & 0xFF;
    iv[3] = iv_value & 0xFF;

    return iv;
}

bool make_md5(
    const uint8_t shared_secret[48],
    uint8_t hash8[8],
    const char* prefix)
{
    if (!shared_secret || !hash8 || !prefix)
        return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
        return false;

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_len = 0;

    bool ok = false;

    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1)
        goto cleanup;

    if (EVP_DigestUpdate(
        ctx,
        prefix,
        std::strlen(prefix)) != 1)
    {
        goto cleanup;
    }

    if (EVP_DigestUpdate(
        ctx,
        shared_secret,
        48) != 1)
    {
        goto cleanup;
    }

    if (EVP_DigestFinal_ex(
        ctx,
        digest,
        &digest_len) != 1)
    {
        goto cleanup;
    }

    if (digest_len < 8)
        goto cleanup;

    std::memcpy(hash8, digest, 8);

    ok = true;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ok;
}

void set_aes_key(const unsigned char* x192, unsigned char* key256)
{
    SHA1_state	skyper = SHA1_INIT;
    u32			n = 0;

    SHA1_update(&skyper, &n, 4);
    SHA1_update(&skyper, x192, 192);
    SHA1_end(&skyper);
    memcpy(key256, skyper.hash, 20);

    n = 0x01000000;
    SHA1_init(&skyper);
    SHA1_update(&skyper, &n, 4);
    SHA1_update(&skyper, x192, 192);
    SHA1_end(&skyper);
    memcpy(key256 + 20, skyper.hash, 12);

    /* printf("\n[INFO] AES-256 key: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02X", key256[i]);
        if (i < 31) printf(" ");
    }
    printf("\n"); */
}

bool decrypt_session_key(RSA* g_private_key, const unsigned char* encrypted_session_key, unsigned char* key256)
{
    unsigned char x192[192] = { 0 };

    int decrypted_len = RSA_private_decrypt(
        192,
        encrypted_session_key,
        x192,
        g_private_key,
        RSA_NO_PADDING
    );

    if (decrypted_len != 192) {
        printf("\n[ERROR] RSA Decryption failed. Dropping packet..");
        return false;
    }

    /* printf("\n[INFO] Decrypted SessionKey: ");
    for (int i = 0; i < 192; ++i) {
        printf("%02X", x192[i]);
        if (i < 191) printf(" ");
    }
    printf("\n"); */

    set_aes_key(x192, key256);
    return true;
}

void aes_ctr(const unsigned char* key256, unsigned char* data, unsigned int len, unsigned int IV, unsigned int IV2, unsigned int IV3, unsigned int IV4)
{
    if (!key256 || !data || len == 0) return;

    /* printf("\n[INFO] AES-256 key: ");
    for (int i = 0; i < 32; ++i) {
        printf("%02X", key256[i]);
        if (i < 31) printf(" ");
    }
    printf("\n"); */

    u32 blk[8] = {IV, IV2, IV3, IV4, 0, 0, 0, 0};
    u32 ks[60];
    u32 i = 0;
    u32 j = 0;

    /* printf("\n[INFO] CTRL BLK: ");
    for (int i = 0; i < 8; i++) {
        printf("%08X ", blk[i]);
    }
    printf("\n"); */

    aes_256_setkey(key256, ks);

    for (j = 0; j + 16 < len; j += 16)
    {
        aes_256_encrypt(blk, blk + 4, ks);

        dword_set(
            data + j + 0,
            dword_get(data + j + 0) ^ bswap32(blk[4])
        );

        dword_set(
            data + j + 4,
            dword_get(data + j + 4) ^ bswap32(blk[5])
        );

        dword_set(
            data + j + 8,
            dword_get(data + j + 8) ^ bswap32(blk[6])
        );

        dword_set(
            data + j + 12,
            dword_get(data + j + 12) ^ bswap32(blk[7])
        );

        ++blk[3];
    }

    if (j < len)
    {
        aes_256_encrypt(blk, blk + 4, ks);

        for (i = 0; j < len; ++j, ++i)
            data[j] ^= ((u8*)(blk + 4))[i ^ 3];
    }
}

uint32_t crc16(const unsigned char* data, unsigned int len)
{
    uint32_t crc = 0xFFFFFFFF;

    for (unsigned int i = 0; i < len; ++i)
    {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
    }

    return ~crc;
}

static bool base64url_decode(
    const std::string& input,
    std::vector<unsigned char>& output)
{
    std::string b64 = input;

    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');

    while (b64.size() % 4)
        b64.push_back('=');

    std::vector<unsigned char> decoded(
        (b64.size() / 4) * 3 + 3
    );

    int len = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const unsigned char*>(b64.data()),
        static_cast<int>(b64.size())
    );

    if (len < 0)
        return false;

    size_t padding = 0;

    if (!b64.empty() && b64.back() == '=')
        ++padding;

    if (b64.size() >= 2 && b64[b64.size() - 2] == '=')
        ++padding;

    if (len < static_cast<int>(padding))
        return false;

    len -= static_cast<int>(padding);

    decoded.resize(static_cast<size_t>(len));
    output = std::move(decoded);

    return true;
}

static bool hex_decode(
    const std::string& hex,
    std::vector<unsigned char>& output)
{
    if (hex.empty() || (hex.size() & 1))
        return false;

    output.clear();
    output.reserve(hex.size() / 2);

    auto hex_value = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';

        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;

        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;

        return -1;
    };

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = hex_value(hex[i]);
        const int lo = hex_value(hex[i + 1]);

        if (hi < 0 || lo < 0)
            return false;

        output.push_back(
            static_cast<unsigned char>((hi << 4) | lo)
        );
    }

    return true;
}

static bool json_get_string(
    const std::string& json,
    const std::string& key,
    std::string& value)
{
    const std::string pattern = "\"" + key + "\"";

    size_t pos = json.find(pattern);
    if (pos == std::string::npos)
        return false;

    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos)
        return false;

    ++pos;

    while (pos < json.size() &&
        (json[pos] == ' ' || json[pos] == '\t' ||
            json[pos] == '\r' || json[pos] == '\n'))
    {
        ++pos;
    }

    if (pos >= json.size() || json[pos] != '"')
        return false;

    ++pos;

    std::string result;

    while (pos < json.size())
    {
        char c = json[pos++];

        if (c == '"')
        {
            value = std::move(result);
            return true;
        }

        if (c == '\\')
        {
            if (pos >= json.size())
                return false;

            char escaped = json[pos++];

            switch (escaped)
            {
            case '"':  result.push_back('"');  break;
            case '\\': result.push_back('\\'); break;
            case '/':  result.push_back('/');  break;
            case 'b':  result.push_back('\b'); break;
            case 'f':  result.push_back('\f'); break;
            case 'n':  result.push_back('\n'); break;
            case 'r':  result.push_back('\r'); break;
            case 't':  result.push_back('\t'); break;

            default:
                return false;
            }
        }
        else
        {
            result.push_back(c);
        }
    }

    return false;
}

static bool json_get_int64(
    const std::string& json,
    const std::string& key,
    int64_t& value)
{
    const std::string pattern = "\"" + key + "\"";

    size_t pos = json.find(pattern);
    if (pos == std::string::npos)
        return false;

    pos = json.find(':', pos + pattern.size());
    if (pos == std::string::npos)
        return false;

    ++pos;

    while (pos < json.size() &&
        (json[pos] == ' ' || json[pos] == '\t' ||
            json[pos] == '\r' || json[pos] == '\n'))
    {
        ++pos;
    }

    if (pos >= json.size())
        return false;

    bool negative = false;

    if (json[pos] == '-')
    {
        negative = true;
        ++pos;
    }

    if (pos >= json.size() ||
        json[pos] < '0' ||
        json[pos] > '9')
    {
        return false;
    }

    int64_t result = 0;

    while (pos < json.size() &&
        json[pos] >= '0' &&
        json[pos] <= '9')
    {
        const int digit = json[pos] - '0';

        if (result > (INT64_MAX - digit) / 10)
            return false;

        result = result * 10 + digit;
        ++pos;
    }

    value = negative ? -result : result;
    return true;
}

bool verify_access_token(
    const std::string& token,
    const std::string& xor_key_hex,
    const std::string& token_secret,
    std::string& uuid)
{
    uuid.clear();
    std::vector<unsigned char> xor_key;

    if (!hex_decode(xor_key_hex, xor_key))
        return false;

    if (xor_key.empty())
        return false;

    std::vector<unsigned char> raw;

    if (!base64url_decode(token, raw))
        return false;

    if (raw.size() < 36)
        return false;

    if (raw[0] != 0x01)
        return false;

    const uint16_t payload_len =
        (static_cast<uint16_t>(raw[1]) << 8) |
        static_cast<uint16_t>(raw[2]);

    const size_t payload_begin = 3;
    const size_t payload_end =
        payload_begin + payload_len;

    if (payload_end + 32 != raw.size())
        return false;


    const unsigned char* encrypted =
        raw.data() + payload_begin;

    const unsigned char* received_hmac =
        raw.data() + payload_end;

    unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
    unsigned int calculated_len = 0;

    HMAC(
        EVP_sha256(),
        token_secret.data(),
        static_cast<int>(token_secret.size()),
        encrypted,
        payload_len,
        calculated_hmac,
        &calculated_len
    );

    if (calculated_len != 32)
        return false;

    if (CRYPTO_memcmp(
        calculated_hmac,
        received_hmac,
        32) != 0)
    {
        return false;
    }

    std::string json;
    json.resize(payload_len);

    for (size_t i = 0; i < payload_len; ++i)
    {
        json[i] = static_cast<char>(
            encrypted[i] ^
            xor_key[i % xor_key.size()]
            );
    }

    std::string iss;
    int64_t exp = 0;

    if (!json_get_string(json, "iss", iss))
        return false;

    if (!json_get_string(json, "sub", uuid))
        return false;

    if (!json_get_int64(json, "exp", exp))
        return false;

    if (iss != "sda")
        return false;

    const int64_t now =
        static_cast<int64_t>(std::time(nullptr));

    if (exp < now)
        return false;

    json_get_string(json, "sub", uuid);
    return true;
}

    
