#pragma once

#include <array>
#include <cstdint>

#include "../../proto/common/skype_basics.h"

struct DH384Session {
    std::array<u8, 48> private_key{};
    std::array<u8, 48> public_key{};
    std::array<u8, 48> shared_key{};
};

bool dh384(
    std::array<u8, 48>& private_key,
    std::array<u8, 48>& public_key);

bool compute_shared(
    const std::array<u8, 48>& private_key,
    const u8 peer_public[48],
    std::array<u8, 48>& shared_key);
