// Skype TCP SuperNode.cpp
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable: 4996)

#include <winsock2.h>
#include <windows.h>
#include <algorithm>
#include <mysql.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <memory>
#include <queue>
#include <array>

#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/applink.c>

#include "proto/common/skype_basics.h"
#include "proto/builder/builder.h"
#include "proto/pack-4142/ext42.h"
#include "proto/parser/parser.h"
#include "proto/common/common.h"
#include "crypto/dh384/dh384.h"
#include "crypto/crypto.h"
#include "config/dotenv.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libmysql.lib")

class MySQLPool {
private:
    std::queue<MYSQL*> pool;
    std::mutex mtx;
    std::string host, user, pass, db;
    int port;
    size_t max_pool_size;
    bool is_running;
    enum mysql_ssl_mode ssl_mode;

    void print_connect_error(MYSQL* conn, const char* stage) const {
        if (!conn) {
            printf("[INFO] %s: mysql_init() failed\n", stage);
            return;
        }

        printf("[INFO] %s failed: errno=%u sqlstate=%s error=%s\n",
            stage,
            mysql_errno(conn),
            mysql_sqlstate(conn),
            mysql_error(conn));
    }

    MYSQL* connect_new() {
        MYSQL* conn = mysql_init(NULL);
        if (!conn) {
            print_connect_error(conn, "mysql_init");
            return nullptr;
        }

        enum mysql_protocol_type protocol = MYSQL_PROTOCOL_TCP;
        if (mysql_options(conn, MYSQL_OPT_PROTOCOL, &protocol) != 0) {
            print_connect_error(conn, "mysql_options(MYSQL_OPT_PROTOCOL)");
            mysql_close(conn);
            return nullptr;
        }

        if (mysql_options(conn, MYSQL_OPT_SSL_MODE, &ssl_mode) != 0) {
            print_connect_error(conn, "mysql_options(MYSQL_OPT_SSL_MODE)");
            mysql_close(conn);
            return nullptr;
        }

        if (!mysql_real_connect(conn,
            host.c_str(),
            user.c_str(),
            pass.c_str(),
            db.c_str(),
            port,
            NULL,
            0)) {
            print_connect_error(conn, "mysql_real_connect");
            mysql_close(conn);
            return nullptr;
        }

        return conn;
    }

public:
    MySQLPool(const std::string& h,
        const std::string& u,
        const std::string& p,
        const std::string& d,
        int pt,
        size_t size,
        enum mysql_ssl_mode sslMode = SSL_MODE_DISABLED)
        : host(h),
        user(u),
        pass(p),
        db(d),
        port(pt),
        max_pool_size(size),
        is_running(true),
        ssl_mode(sslMode) {
        for (size_t i = 0; i < max_pool_size; ++i) {
            MYSQL* conn = connect_new();
            if (conn) {
                pool.push(conn);
            }
            else {
                printf("[INFO] Pool connection %zu/%zu failed\n",
                    i + 1,
                    max_pool_size);
            }
        }

        if (pool.empty()) {
            printf("[ERROR] MySQL pool initialization failed: 0/%zu connections available\n",
                max_pool_size);
        }
        else {
            printf("\n[INFO] Successful MySQL Connection",
                pool.size(),
                max_pool_size);
        }
    }

    ~MySQLPool() {
        std::lock_guard<std::mutex> lock(mtx);
        is_running = false;
        while (!pool.empty()) {
            MYSQL* conn = pool.front();
            pool.pop();
            mysql_close(conn);
        }
    }

    MYSQL* acquire() {
        std::unique_lock<std::mutex> lock(mtx);

        if (pool.empty()) {
            return connect_new();
        }

        MYSQL* conn = pool.front();
        pool.pop();

        if (mysql_ping(conn) != 0) {
            print_connect_error(conn, "mysql_ping");
            mysql_close(conn);
            conn = connect_new();
            if (!conn) {
                return nullptr;
            }
        }

        return conn;
    }

    void release(MYSQL* conn) {
        if (!conn) return;
        std::lock_guard<std::mutex> lock(mtx);
        if (is_running && pool.size() < max_pool_size) {
            pool.push(conn);
        }
        else {
            mysql_close(conn);
        }
    }
};

MySQLPool* g_db_pool = nullptr;
std::string token_secret;
std::string xor_key;
RSA* g_auth_key = NULL;
RSA* g_cred_key = NULL;

void print_hex_dump(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
        if (i < len - 1) printf(" ");
    }

    printf("\n");
}

int send_tcp_packet(SOCKET sockfd, const void* data, size_t len, const std::string& client_ip, int client_port) {
    int sent = send(sockfd, (const char*)data, len, 0);

    if (sent != SOCKET_ERROR) {
        printf("\n[INFO] Sent %d bytes to %s:%d: ",
            sent,
            client_ip.c_str(),
            client_port);

        const unsigned char* bytes = (const unsigned char*)data;
        for (int i = 0; i < sent && i < len; i++) {
            printf("%02X", bytes[i]);
            if (i < sent - 1) printf(" ");
        }
        printf("\n");
    }
    else {
        printf("[ERROR] Failed to send packet: %d\n", WSAGetLastError());
    }

    return sent;
}

bool load_auth_key(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        printf("[ERROR] Failed to open private key: %s\n", path);
        return false;
    }

    g_auth_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!g_auth_key) {
        printf("[ERROR] Failed to read private key\n");
        return false;
    }

    return true;
}

bool load_cred_key(const char* path) {
    FILE* fp = fopen(path, "r");
    if (!fp) {
        printf("[ERROR] Failed to open private key: %s\n", path);
        return false;
    }

    g_cred_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!g_cred_key) {
        printf("[ERROR] Failed to read private key\n");
        return false;
    }

    return true;
}

uint64_t make_addr(uint32_t ip, uint16_t port) {
    return ((uint64_t)ip << 16) | port;
}

uint32_t get_ip(uint64_t addr) {
    return (uint32_t)(addr >> 16);
}

uint16_t get_port(uint64_t addr) {
    return (uint16_t)(addr & 0xFFFF);
}

struct Peer {
    uint64_t client_addr;
    bool authenticated = false;
    std::string state;

    RC4_context recv_rc4;
    RC4_context send_rc4;
    uint8_t dh_private[48]{};
    uint8_t dh_public[48]{};
    uint8_t dh_shared[48]{};

    uint8_t aes_key[32]{};
    bool aes_ready = false;

    std::array<unsigned char, 128> client_modulus{};
    bool has_client_modulus = false;

    std::string access_token;
    std::string site_name;
    std::string client_version;
    std::string locale;
    int partner_id = 0;

    std::vector<uint8_t> recv_key;
    std::vector<uint8_t> send_key;

    Peer() : state("HANDSHAKE") {}
    Peer(const std::string& initial_state) : state(initial_state) {}
};

struct ClientSession {
    SOCKET socket = INVALID_SOCKET;
    sockaddr_in addr{};
    Peer peer;

    std::mutex send_mutex;
    uint16_t next_send_seq = 0;

    std::vector<uint8_t> rx_pending;
    std::atomic_bool registered{ false };

    ClientSession(SOCKET s, const sockaddr_in& a)
        : socket(s), addr(a), peer("HANDSHAKE") {}
};

std::mutex sessions_mutex;
std::vector<std::shared_ptr<ClientSession>> sessions;
std::atomic<uint32_t> clients_online = 0;

static std::vector<std::shared_ptr<ClientSession>> get_registered_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    return sessions;
}

static void send_netstats_to_session(
    const std::shared_ptr<ClientSession>& session,
    uint32_t online_count)
{
    if (!session || !session->registered.load() ||
        session->socket == INVALID_SOCKET) {
        return;
    }

    std::lock_guard<std::mutex> send_lock(session->send_mutex);

    if (!session->registered.load() || session->socket == INVALID_SOCKET) {
        return;
    }

    const std::string ip = inet_ntoa(session->addr.sin_addr);
    const int port = ntohs(session->addr.sin_port);

    std::vector<uint8_t> pkt = build_tcp_pkt3(
        session->next_send_seq,
        online_count,
        &session->peer.send_rc4
    );

    if (send_tcp_packet(
        session->socket,
        pkt.data(),
        pkt.size(),
        ip,
        port) != SOCKET_ERROR) {
        ++session->next_send_seq;
    }
}

static void broadcast_netstats(
    uint32_t online_count,
    SOCKET excluded_socket = INVALID_SOCKET)
{
    std::vector<std::shared_ptr<ClientSession>> snapshot;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        snapshot = sessions;
    }

    for (const auto& session : snapshot) {
        if (!session || session->socket == excluded_socket) {
            continue;
        }

        send_netstats_to_session(session, online_count);
    }
}

static void register_session(
    const std::shared_ptr<ClientSession>& session,
    uint16_t seq)
{
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);

        if (session->registered.load()) {
            return;
        }

        session->next_send_seq = static_cast<uint16_t>(seq + 2);
        session->registered.store(true);
        sessions.push_back(session);
    }

    ++clients_online;
}

static void unregister_session(
    const std::shared_ptr<ClientSession>& session)
{
    if (!session || !session->registered.exchange(false)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(sessions_mutex);

        auto it = std::find(sessions.begin(), sessions.end(), session);
        if (it != sessions.end()) {
            sessions.erase(it);
        }
    }

    uint32_t previous = clients_online.load();
    while (previous > 0 &&
        !clients_online.compare_exchange_weak(previous, previous - 1)) {
    }

    const uint32_t new_count = clients_online.load();
    broadcast_netstats(new_count, session->socket);
}

std::string GetUsernameByUUID(const std::string& uuid)
{
    if (!g_db_pool) {
        printf("[INFO] GetUsernameByUUID: MySQL pool is not initialized\n");
        return std::string();
    }

    if (uuid.empty()) {
        printf("[INFO] GetUsernameByUUID: UUID is empty\n");
        return std::string();
    }

    MYSQL* conn = g_db_pool->acquire();
    if (!conn) {
        printf("[INFO] GetUsernameByUUID: failed to acquire MySQL connection\n");
        return std::string();
    }

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt) {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_init failed: %s\n",
            mysql_error(conn));

        g_db_pool->release(conn);
        return std::string();
    }

    const char* query =
        "SELECT username "
        "FROM skype_users "
        "WHERE uuid = UUID_TO_BIN(?, 1) "
        "LIMIT 1";

    if (mysql_stmt_prepare(
        stmt,
        query,
        static_cast<unsigned long>(strlen(query))) != 0)
    {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_prepare failed: %s\n",
            mysql_stmt_error(stmt));

        mysql_stmt_close(stmt);
        g_db_pool->release(conn);
        return std::string();
    }

    // UUID parameter
    MYSQL_BIND param;
    memset(&param, 0, sizeof(param));

    param.buffer_type = MYSQL_TYPE_STRING;
    param.buffer = const_cast<char*>(uuid.c_str());
    param.buffer_length = static_cast<unsigned long>(uuid.size());

    if (mysql_stmt_bind_param(stmt, &param) != 0) {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_bind_param failed: %s\n",
            mysql_stmt_error(stmt));

        mysql_stmt_close(stmt);
        g_db_pool->release(conn);
        return std::string();
    }

    if (mysql_stmt_execute(stmt) != 0) {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_execute failed: %s\n",
            mysql_stmt_error(stmt));

        mysql_stmt_close(stmt);
        g_db_pool->release(conn);
        return std::string();
    }

    // Buffer the result
    if (mysql_stmt_store_result(stmt) != 0) {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_store_result failed: %s\n",
            mysql_stmt_error(stmt));

        mysql_stmt_close(stmt);
        g_db_pool->release(conn);
        return std::string();
    }

    char username_buffer[256] = {};
    unsigned long username_length = 0;
    my_bool username_is_null = 0;

    MYSQL_BIND result;
    memset(&result, 0, sizeof(result));

    result.buffer_type = MYSQL_TYPE_STRING;
    result.buffer = username_buffer;
    result.buffer_length = sizeof(username_buffer) - 1;
    result.length = &username_length;
    result.is_null = &username_is_null;

    if (mysql_stmt_bind_result(stmt, &result) != 0) {
        printf("[INFO] GetUsernameByUUID: mysql_stmt_bind_result failed: %s\n",
            mysql_stmt_error(stmt));

        mysql_stmt_free_result(stmt);
        mysql_stmt_close(stmt);
        g_db_pool->release(conn);
        return std::string();
    }

    std::string username;

    int fetch_result = mysql_stmt_fetch(stmt);

    if (fetch_result == 0) {

        if (!username_is_null) {
            username.assign(username_buffer, username_length);
        }
    }
    else if (fetch_result == MYSQL_NO_DATA) {

        printf("[INFO] GetUsernameByUUID: user not found: %s\n",
            uuid.c_str());
    }
    else if (fetch_result == MYSQL_DATA_TRUNCATED) {

        printf("[INFO] GetUsernameByUUID: username is too long: %s\n",
            uuid.c_str());
    }
    else {

        printf("[INFO] mysql_stmt_fetch failed: %s\n",
            mysql_stmt_error(stmt));
    }

    mysql_stmt_free_result(stmt);
    mysql_stmt_close(stmt);
    g_db_pool->release(conn);

    return username;
}

static void handle_client(SOCKET client_socket, sockaddr_in client_addr) {
    auto session = std::make_shared<ClientSession>(client_socket, client_addr);

    const std::string client_ip = inet_ntoa(client_addr.sin_addr);
    const int client_port = ntohs(client_addr.sin_port);

    const int BUFFER_SIZE = 65535;
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    Peer& peer = session->peer;

    printf("\n[INFO] Work with client: %s:%d\n",
        client_ip.c_str(),
        client_port,
        static_cast<unsigned long long>(client_socket));

    while (true) {
        int recv_len = recv(client_socket, (char*)buffer.data(), BUFFER_SIZE, 0);

        if (recv_len <= 0) {
            break;
        }

        printf("\n[INFO] Received %d bytes from %s:%d: ",
            recv_len,
            client_ip.c_str(),
            client_port);
        print_hex_dump(buffer.data(), recv_len);

        if (peer.state == "HANDSHAKE") {
            printf("[INFO] Received Skype HandShake. Processing..");

            if (recv_len == 14) {
                uint32_t iv_value = (buffer[0] << 24) | (buffer[1] << 16) |
                    (buffer[2] << 8) | buffer[3];

                std::vector<uint8_t> iv(4);
                iv[0] = (iv_value >> 24) & 0xFF;
                iv[1] = (iv_value >> 16) & 0xFF;
                iv[2] = (iv_value >> 8) & 0xFF;
                iv[3] = iv_value & 0xFF;

                peer.recv_key = get_rc4_key(iv, NULL, 0);
                create_rc4_stream(&peer.recv_rc4, peer.recv_key);

                std::vector<uint8_t> encrypted_body(10);
                memcpy(encrypted_body.data(), buffer.data() + 4, 10);

                RC4_crypt(encrypted_body.data(), 10, &peer.recv_rc4, false);

                printf("\n\n[INFO] Decrypyed body: ");
                print_hex_dump(encrypted_body.data(), 10);

                uint8_t packetType = encrypted_body[9];

                switch (packetType) {
                    case PKT_TYPE_CTRL: {
                        printf("[INFO] Received PKT_TYPE_CTRL. Processing..\n");

                        std::vector<uint8_t> send_iv = generate_random_iv();
                        std::vector<uint8_t> send_rc4_key = get_rc4_key(send_iv, NULL, 0);

                        peer.send_key.assign(send_rc4_key.begin(), send_rc4_key.begin() + 80);
                        create_rc4_stream(&peer.send_rc4, peer.send_key);

                        std::vector<uint8_t> tcp_pkt1 = build_tcp_pkt1(send_iv, &peer.send_rc4);
                        send_tcp_packet(client_socket, tcp_pkt1.data(), tcp_pkt1.size(), client_ip, client_port);

                        create_rc4_stream(&peer.recv_rc4, peer.recv_key);
                        create_rc4_stream(&peer.send_rc4, peer.send_key);

                        peer.state = "ACCEPT";
                        break;
                    }
                    default: {
                        printf("[INFO] Unmanaged packetType: 0x%02X. Dropping packet..\n", packetType);

                        unregister_session(session);
                        closesocket(client_socket);
                        return;
                    }
                }
            }
            else if (recv_len >= 48) {
                DH384Session dh;

                if (!dh384(
                    dh.private_key,
                    dh.public_key))
                {
                    printf("[INFO] DH-384 generation failed\n");

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }

                uint8_t client_public[48];
                std::memcpy(client_public, buffer.data(), 48);

                if (!compute_shared(
                    dh.private_key,
                    client_public,
                    dh.shared_key))
                {
                    printf("[INFO] Failed to compute shared secret\n");

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }

                std::memcpy(
                    peer.dh_private,
                    dh.private_key.data(),
                    dh.private_key.size()
                );

                std::memcpy(
                    peer.dh_public,
                    dh.public_key.data(),
                    dh.public_key.size()
                );

                std::memcpy(
                    peer.dh_shared,
                    dh.shared_key.data(),
                    dh.shared_key.size()
                );

                printf("\n");
                send_tcp_packet(client_socket, dh.public_key.data(), dh.public_key.size(), client_ip, client_port);
                peer.state = "MD5";
            }
        }
        else if (peer.state == "MD5") {
            if (recv_len < 8) {
                printf("\n[INFO] MD5 packet too short: %d bytes\n", recv_len);

                unregister_session(session);
                closesocket(client_socket);
                return;
            }

            uint8_t received_md5[8];
            std::memcpy(received_md5, buffer.data(), 8);

            printf("\n[INFO] Received MD5: ");
            for (int i = 0; i < 8; ++i)
                printf("%02X%s",
                    received_md5[i],
                    i == 7 ? "\n" : " ");

            uint8_t computed_md5[8];

            if (!make_md5(peer.dh_shared, computed_md5, "O")) {
                printf("[INFO] Failed to calculate MD5\n");

                unregister_session(session);
                closesocket(client_socket);
                return;
            }

            printf("[INFO] Computed MD5: ");
            for (int i = 0; i < 8; ++i)
                printf("%02X%s",
                    computed_md5[i],
                    i == 7 ? "\n" : " ");

            if (std::memcmp(computed_md5, received_md5, 8) == 0) {
                printf("\n[INFO] MD5 is match!");

                uint8_t computed_i_md5[8];

                if (!make_md5(peer.dh_shared, computed_i_md5, "I")) {
                    printf("[INFO] Failed to calculate MD5\n");

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }

                send_tcp_packet(client_socket, computed_i_md5, sizeof(computed_i_md5), client_ip, client_port);

                peer.recv_key.assign(
                    peer.dh_shared,
                    peer.dh_shared + sizeof(peer.dh_shared)
                );

                peer.send_key.assign(
                    peer.dh_shared,
                    peer.dh_shared + sizeof(peer.dh_shared)
                );

                peer.send_key[0] =
                    static_cast<uint8_t>(peer.send_key[0] + 1);

                create_rc4_stream(
                    &peer.recv_rc4,
                    peer.recv_key
                );

                create_rc4_stream(
                    &peer.send_rc4,
                    peer.send_key
                );

                peer.state = "TCP_AUTH";
            }
            else {
                printf("\n[INFO] MD5 mismatch! Dropping client..\n");

                unregister_session(session);
                closesocket(client_socket);
                return;
            }
        }
        else if (peer.state == "TCP_AUTH") {
            session->rx_pending.insert(
                session->rx_pending.end(),
                buffer.begin(),
                buffer.begin() + recv_len
            );

            while (true) {
                if (session->rx_pending.size() < 5)
                    break;

                RC4_context probe = peer.recv_rc4;

                uint8_t header[5];
                memcpy(header, session->rx_pending.data(), 5);

                RC4_crypt(
                    header,
                    5,
                    &probe,
                    false
                );

                const uint8_t recordType = header[0];
                const uint8_t versionMajor = header[1];
                const uint8_t versionMinor = header[2];

                const uint16_t body_len =
                    (static_cast<uint16_t>(header[3]) << 8) |
                    static_cast<uint16_t>(header[4]);

                if (versionMajor != 3 || versionMinor != 1) {
                    printf("[INFO] Unexpected record version %u.%u\n", (unsigned)versionMajor, (unsigned)versionMinor);

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }

                const size_t total_len =
                    5u + static_cast<size_t>(body_len);

                if (session->rx_pending.size() < total_len)
                    break;

                std::vector<uint8_t> packet(
                    session->rx_pending.begin(),
                    session->rx_pending.begin() + total_len
                );

                RC4_crypt(
                    packet.data(),
                    packet.size(),
                    &peer.recv_rc4,
                    false
                );

                printf("\n[INFO] Decrypted body: ");
                print_hex_dump(packet.data(), packet.size());

                std::vector<uint8_t> body(
                    packet.begin() + 5,
                    packet.end()
                );

                session->rx_pending.erase(
                    session->rx_pending.begin(),
                    session->rx_pending.begin() + total_len
                );

                if (recordType == 0x16) {
                    if (body.size() < 192) {
                    }

                    std::vector<uint8_t> x192(192);
                    u32 x192_size = 0;

                    if (!main_unpack_get_binary(
                        body.data(),
                        static_cast<u32>(body.size()),
                        4,
                        0x08,
                        x192.data(),
                        192,
                        &x192_size))
                    {
                        peer.aes_ready = false;
                        continue;
                    }

                    if (x192_size != 192) {
                        peer.aes_ready = false;
                        continue;
                    }

                    if (!decrypt_session_key(
                        g_auth_key,
                        x192.data(),
                        peer.aes_key))
                    {
                        peer.aes_ready = false;
                        continue;
                    }

                    peer.aes_ready = true;
                }
                else if (recordType == 0x17) {
                    if (!peer.aes_ready) {
                        printf("[INFO] ApplicationData record received before AES session key was established\n");
                        continue;
                    }

                    if (!body.empty()) {
                        aes_ctr(peer.aes_key, body.data(), static_cast<unsigned int>(body.size()), 0, 0, 0, 0);
                    }

                    printf("\n[INFO] Decrypted body: ", body.size());
                    if (!body.empty()) {
                        print_hex_dump(body.data(), body.size());
                    }
                    else {
                        printf("<empty>\n");
                    }

                    tcp_auth_data login_data;

                    if (parse_tcp_auth(
                        reinterpret_cast<const unsigned char*>(body.data()),
                        body.size(),
                        login_data))
                    {
                        peer.access_token = login_data.access_token;
                        peer.site_name = login_data.site_name;
                        peer.client_version = login_data.client_version;
                        peer.locale = login_data.locale;
                        peer.partner_id = login_data.partner_id;

                        if (login_data.has_client_modulus) {
                            peer.client_modulus = login_data.client_modulus;

                            printf("\n[INFO] Client RSA modulus: ");
                            print_hex_dump(
                                peer.client_modulus.data(),
                                peer.client_modulus.size()
                            );
                        }

                        printf("[INFO] accessToken=%s\n", peer.access_token.c_str());
                        printf("[INFO] clientVer=%s\n", peer.client_version.c_str());
                        printf("[INFO] siteName=%s\n", peer.site_name.c_str());
                        printf("[INFO] locale=%s\n", login_data.locale.c_str());
                        printf("[INFO] partnerId=%d\n", peer.partner_id);

                        std::string uuid;
                        uint8_t seq = body[8];

                        if (verify_access_token(peer.access_token, xor_key, token_secret, uuid))
                        {
                            printf("\n[INFO] accessToken is valid for: %s\n", uuid.c_str());
                            std::string username = GetUsernameByUUID(uuid);

                            if (!username.empty()) {
                                printf("[INFO] User found in database for UUID: %s\n", username.c_str());
                            }
                            else {
                                printf("[INFO] user not found for UUID: %s\n", uuid.c_str());
                            }

                            std::vector<unsigned char> uic_payload = build_uic(
                                username.c_str(),
                                peer.client_modulus.data(),
                                0x0BBBD6F1,
                                0x0BD99AF1
                            );

                            std::vector<unsigned char> uic = uic_payload.empty()
                                ? std::vector<unsigned char>()
                                : finalize_uic(g_cred_key, uic_payload, 0x00000001);

                            std::vector<uint8_t> tcp_auth_response = build_auth_response(
                                peer.aes_key,
                                &peer.send_rc4,
                                4200,
                                seq,
                                uic.data(),
                                static_cast<uint32_t>(uic.size())
                            );
                            send_tcp_packet(client_socket, tcp_auth_response.data(), tcp_auth_response.size(), client_ip, client_port);
                        }
                        else
                        {
                            printf("\n[INFO] Invalid accessToken. Sending Login Fail..");

                            std::vector<uint8_t> tcp_auth_response = build_auth_response(
                                peer.aes_key,
                                &peer.send_rc4,
                                4200,
                                seq,
                                NULL,
                                0
                            );
                            send_tcp_packet(client_socket, tcp_auth_response.data(), tcp_auth_response.size(), client_ip, client_port);
                        }
                    }
                }
                else {
                    printf(
                        "[INFO] Unknown TLS record type 0x%02X. Dropping connection..\n",
                        (unsigned)recordType,
                        body.size()
                    );

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }
            }
        }
        else if (peer.state == "ACCEPT") {
            printf("[INFO] Received Client Accept. Processing..");

            std::vector<uint8_t> header(3);
            memcpy(header.data(), buffer.data(), 3);

            RC4_crypt(header.data(), 3, &peer.recv_rc4, false);

            size_t body_len = recv_len - 3;
            std::vector<uint8_t> body(body_len);
            memcpy(body.data(), buffer.data() + 3, body_len);

            RC4_crypt(body.data(), body_len, &peer.recv_rc4, false);

            std::vector<uint8_t> decrypted_packet;
            decrypted_packet.insert(decrypted_packet.end(), header.begin(), header.end());
            decrypted_packet.insert(decrypted_packet.end(), body.begin(), body.end());

            printf("\n\n[INFO] Decrypted body: ");
            print_hex_dump(decrypted_packet.data(), decrypted_packet.size());

            uint16_t cmd = 0;

            if (decrypted_packet.size() >= 6) {
                cmd = (decrypted_packet[4] << 8) | decrypted_packet[5];
            }

            switch (cmd) {
                case CMD_CLIENT: {
                    printf("[INFO] Received CMD_CLIENT. Processing..\n");

                    peer.client_addr = make_addr(
                        client_addr.sin_addr.s_addr,
                        htons(client_port));

                    uint16_t seq = (decrypted_packet[1] << 8) | decrypted_packet[2];
                    uint16_t requestID = (decrypted_packet[6] << 8) | decrypted_packet[7];

                    const bool first_auth = !peer.authenticated;

                    if (first_auth) {
                        peer.authenticated = true;
                        register_session(session, seq);
                    }

                    std::vector<uint8_t> tcp_pkt2 = build_tcp_pkt2(
                        seq,
                        requestID,
                        0x2C,
                        0x2FCDB925,
                        client_addr,
                        &peer.send_rc4
                    );

                    std::vector<uint8_t> tcp_pkt3 = build_tcp_pkt3(
                        seq + 1,
                        clients_online.load(),
                        &peer.send_rc4
                    );

                    {
                        std::lock_guard<std::mutex> send_lock(session->send_mutex);

                        send_tcp_packet(client_socket, tcp_pkt2.data(), tcp_pkt2.size(), client_ip, client_port);
                        send_tcp_packet(client_socket, tcp_pkt3.data(), tcp_pkt3.size(), client_ip, client_port);
                    }

                    printf("[INFO] Clients online: %u\n", clients_online.load());

                    if (first_auth) {
                        broadcast_netstats(
                            clients_online.load(),
                            client_socket
                        );
                    }

                    peer.state = "CONNECTED";
                    break;
                }
                default: {
                    printf("[INFO] Unmanaged cmd: 0x%02X. Dropping packet..\n\n", cmd);

                    unregister_session(session);
                    closesocket(client_socket);
                    return;
                }
            }
        }
        else if (peer.state == "CONNECTED") {
            printf("[INFO] Received Skype Packet. Processing..\n");
            std::vector<uint8_t> decrypted_packet(recv_len);
            memcpy(decrypted_packet.data(), buffer.data(), recv_len);

            RC4_crypt(decrypted_packet.data(), recv_len, &peer.recv_rc4, false);

            printf("\n[INFO] Decrypted body: ");
            print_hex_dump(decrypted_packet.data(), recv_len);

            if (recv_len == 4 && decrypted_packet[0] == 0x07 && decrypted_packet[1] == 0x01) {
                printf("[INFO] Received ACK. Processing..\n");
                uint16_t seq = (decrypted_packet[2] << 8) | decrypted_packet[3];

                std::lock_guard<std::mutex> send_lock(session->send_mutex);

                std::vector<uint8_t> ack = build_tcp_ack(
                    seq,
                    &peer.send_rc4
                );
                send_tcp_packet(client_socket, ack.data(), ack.size(), client_ip, client_port);
            }
            else if (recv_len == 11) {
                uint8_t cmd = decrypted_packet[3];

                switch (cmd) {
                    case CMD_SLOTINFO:
                        printf("[INFO] Received SLOTINFO Request. Processing..\n");
                        break;
                    }
            }
        }
    }

    printf("\n[INFO] Client %s:%d disconnected\n",
        client_ip.c_str(),
        client_port);

    unregister_session(session);
    closesocket(client_socket);

    printf("[INFO] Clients online: %u\n", clients_online.load());
}

int main() {
    SetConsoleTitleA("Skype TCP SuperNode");
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[ERROR] Error initializing WinSock\n");
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if (!load_auth_key("crypto/SSL/private_1536.pem")) {
        printf("[ERROR] Failed to load private key. Exiting...\n");
        WSACleanup();
        return 1;
    }

    if (!load_cred_key("crypto/SSL/private_2048.pem")) {
        printf("[ERROR] Failed to load private key. Exiting...\n");
        WSACleanup();
        return 1;
    }

    dotenv env("config/config.env");
    std::string tcp_host = env.get("skype_tcp_host");
    std::string tcp_port = env.get("skype_tcp_port");
    std::string db_host = env.get("db_host");
    std::string db_user = env.get("db_user");
    std::string db_pass = env.get("db_pass");
    std::string db_name = env.get("db_name");
    int db_port = std::stoi(env.get("db_port").empty() ? "3306" : env.get("db_port"));

    token_secret = env.get("token_secret");
    xor_key = env.get("xor_key");

    if (tcp_host.empty()) tcp_host = "127.0.0.1";
    if (tcp_port.empty()) tcp_port = "33033";

    int port = std::stoi(tcp_port);

    printf("Skype TCP SuperNode is running on: tcp://%s:%d\n", tcp_host.c_str(), port);
    printf("Waiting for connection...\n");

    g_db_pool = new MySQLPool(db_host, db_user, db_pass, db_name, db_port, 5);
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, 0);

    printf("\n[INFO] Clients online: %u\n", clients_online.load());

    if (listen_socket == INVALID_SOCKET) {
        printf("\n[ERROR] Error creating socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL reuse = TRUE;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
        reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(tcp_host.c_str());
    server_addr.sin_port = htons(port);

    if (bind(listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("\n[ERROR] Error binding socket: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("[ERROR] Error listening: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    while (true) {
        sockaddr_in client_addr;
        int client_len = sizeof(client_addr);

        SOCKET client_socket = accept(
            listen_socket,
            (struct sockaddr*)&client_addr,
            &client_len);

        if (client_socket == INVALID_SOCKET) {
            printf("[ERROR] Socket error: %d\n", WSAGetLastError());
            continue;
        }

        try {
            std::thread(handle_client, client_socket, client_addr).detach();
        }
        catch (const std::exception& e) {
            printf("[ERROR] Failed to start client thread: %s\n", e.what());
            closesocket(client_socket);
        }
    }

    closesocket(listen_socket);
    WSACleanup();
    return 0;
}