#include <string>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "parser.h"

namespace {

    static bool is_printable_ascii(
        const unsigned char* ptr,
        const unsigned char* end)
    {
        if (ptr >= end)
            return false;

        const unsigned char* p = ptr;
        while (p < end && *p != 0) {
            if (*p < 0x20 || *p > 0x7E)
                return false;
            p++;
        }

        return p < end;
    }

    static bool find_string_attr(
        const unsigned char* data,
        size_t size,
        unsigned char wanted_tag,
        std::string& out)
    {
        if (!data || size < 3)
            return false;

        const unsigned char* ptr = data;
        const unsigned char* end = data + size;

        while (ptr + 2 < end) {
            if (ptr[0] != 0x03 || ptr[1] != wanted_tag) {
                ptr++;
                continue;
            }

            const unsigned char* value = ptr + 2;

            if (!is_printable_ascii(value, end)) {
                ptr++;
                continue;
            }

            const unsigned char* p = value;
            while (p < end && *p != 0)
                p++;

            if (p >= end)
                return false;

            out.assign(
                reinterpret_cast<const char*>(value),
                static_cast<size_t>(p - value));

            return true;
        }

        return false;
    }

    static bool find_client_modulus(
        const unsigned char* data,
        size_t size,
        std::array<unsigned char, 128>& out_modulus)
    {
        if (!data || size < 4 + 128)
            return false;

        for (size_t i = 0; i + 4 + 128 <= size; ++i) {
            if (data[i] != 0x04 || data[i + 1] != 0x21)
                continue;

            if (data[i + 2] != 0x80 || data[i + 3] != 0x01)
                continue;

            std::memcpy(
                out_modulus.data(),
                data + i + 4,
                out_modulus.size());

            return true;
        }

        return false;
    }

    static bool find_partner_id(
        const unsigned char* data,
        size_t size,
        int& out_partner_id)
    {
        if (!data || size < 10)
            return false;

        for (size_t i = 0; i + 10 <= size; ++i) {
            if (data[i + 0] != 0x01 || data[i + 1] != 0x3E)
                continue;

            uint64_t value =
                (static_cast<uint64_t>(data[i + 2]) << 56) |
                (static_cast<uint64_t>(data[i + 3]) << 48) |
                (static_cast<uint64_t>(data[i + 4]) << 40) |
                (static_cast<uint64_t>(data[i + 5]) << 32) |
                (static_cast<uint64_t>(data[i + 6]) << 24) |
                (static_cast<uint64_t>(data[i + 7]) << 16) |
                (static_cast<uint64_t>(data[i + 8]) << 8) |
                (static_cast<uint64_t>(data[i + 9]) << 0);

            if (value <= 0x7FFFFFFF) {
                out_partner_id = static_cast<int>(value);
                return true;
            }
        }

        return false;
    }

}

bool parse_tcp_auth(
    const unsigned char* data,
    size_t size,
    tcp_auth_data& out_data)
{
    out_data = {};

    if (!data || size == 0)
        return false;

    const bool ok_access_token =
        find_string_attr(data, size, 0x3D, out_data.access_token);

    const bool ok_site_name =
        find_string_attr(data, size, 0x45, out_data.site_name);

    const bool ok_client_version =
        find_string_attr(data, size, 0x0D, out_data.client_version);

    find_string_attr(data, size, 0x36, out_data.locale);
    find_partner_id(data, size, out_data.partner_id);

    out_data.has_client_modulus =
        find_client_modulus(
            data,
            size,
            out_data.client_modulus);

    return ok_access_token &&
        ok_site_name &&
        ok_client_version &&
        out_data.has_client_modulus;
}
