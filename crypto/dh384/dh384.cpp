#include "dh384.h"

#include <array>
#include <cstdint>
#include <cstring>

#include <openssl/bn.h>
#include <openssl/rand.h>

namespace {
    constexpr char skype_dh384_modulus[] =
        "FFFFFFFFFFFFFFFF"
        "C90FDAA22168C234"
        "C4C6628B80DC1CD1"
        "29024E088A67CC74"
        "020BBEA63B13B202"
        "FFFFFFFFFFFFFFFF";

    bool bn_to_48(
        const BIGNUM* value,
        std::array<u8, 48>& out)
    {
        if (!value)
            return false;

        return BN_bn2binpad(
            value,
            out.data(),
            48
        ) == 48;
    }

}

bool dh384(
    std::array<u8, 48>& private_key,
    std::array<u8, 48>& public_key)
{
    BN_CTX* ctx = nullptr;
    BIGNUM* p = nullptr;
    BIGNUM* g = nullptr;
    BIGNUM* a = nullptr;
    BIGNUM* A = nullptr;

    bool ok = false;

    ctx = BN_CTX_new();
    p = BN_new();
    g = BN_new();
    a = BN_new();
    A = BN_new();

    if (!ctx || !p || !g || !a || !A)
        goto cleanup;

    if (!BN_hex2bn(&p, skype_dh384_modulus))
        goto cleanup;

    if (!BN_set_word(g, 2))
        goto cleanup;

    if (RAND_bytes(
        private_key.data(),
        static_cast<int>(private_key.size())) != 1)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(
        private_key.data(),
        48,
        a))
    {
        goto cleanup;
    }

    if (!BN_mod_exp(
        A,
        g,
        a,
        p,
        ctx))
    {
        goto cleanup;
    }

    if (!bn_to_48(A, public_key))
        goto cleanup;

    ok = true;

cleanup:
    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(A);
    BN_CTX_free(ctx);

    return ok;
}

bool compute_shared(
    const std::array<u8, 48>& private_key,
    const u8 peer_public[48],
    std::array<u8, 48>& shared_secret)
{
    BN_CTX* ctx = nullptr;
    BIGNUM* p = nullptr;
    BIGNUM* a = nullptr;
    BIGNUM* B = nullptr;
    BIGNUM* S = nullptr;

    bool ok = false;

    if (!peer_public)
        return false;

    ctx = BN_CTX_new();
    p = BN_new();
    S = BN_new();

    if (!ctx || !p || !S)
        goto cleanup;

    if (!BN_hex2bn(&p, skype_dh384_modulus))
        goto cleanup;

    a = BN_bin2bn(private_key.data(), 48, nullptr);
    B = BN_bin2bn(peer_public, 48, nullptr);

    if (!a || !B)
        goto cleanup;

    if (!BN_mod_exp(
        S,
        B,
        a,
        p,
        ctx))
    {
        goto cleanup;
    }

    if (!bn_to_48(S, shared_secret))
        goto cleanup;

    ok = true;

cleanup:
    BN_free(p);
    BN_free(a);
    BN_free(B);
    BN_free(S);
    BN_CTX_free(ctx);

    return ok;
}
