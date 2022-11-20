#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

#ifdef __GNUC__
#pragma GCC target("ssse3")
#pragma GCC target("aes")
#endif

#ifdef __x86_64__

#include <tmmintrin.h>
#include <wmmintrin.h>

typedef __m128i aes_block_t;
#define AES_BLOCK_XOR(A, B)       _mm_xor_si128((A), (B))
#define AES_BLOCK_AND(A, B)       _mm_and_si128((A), (B))
#define AES_BLOCK_LOAD(A)         _mm_loadu_si128((const aes_block_t *) (const void *) (A))
#define AES_BLOCK_LOAD_64x2(A, B) _mm_set_epi64x((A), (B))
#define AES_BLOCK_STORE(A, B)     _mm_storeu_si128((aes_block_t *) (void *) (A), (B))
#define AES_ENC(A, B)             _mm_aesenc_si128((A), (B))

#elif defined(__aarch64__)

#include <arm_neon.h>

typedef uint8x16_t aes_block_t;
#define AES_BLOCK_XOR(A, B)       veorq_u8((A), (B))
#define AES_BLOCK_AND(A, B)       vandq_u8((A), (B))
#define AES_BLOCK_LOAD(A)         vld1q_u8(A)
#define AES_BLOCK_LOAD_64x2(A, B) vreinterpretq_u8_u64(vsetq_lane_u64((A), vmovq_n_u64(B), 1))
#define AES_BLOCK_STORE(A, B)     vst1q_u8((A), (B))
#define AES_ENC(A, B)             veorq_u8(vaesmcq_u8(vaeseq_u8((A), vmovq_n_u8(0))), (B))

#else
#error "Unsupported architecture"
#endif

static inline void
crypto_aead_aegis128l_update(aes_block_t *const state, const aes_block_t d1, const aes_block_t d2)
{
    aes_block_t tmp;

    tmp      = state[7];
    state[7] = AES_ENC(state[6], state[7]);
    state[6] = AES_ENC(state[5], state[6]);
    state[5] = AES_ENC(state[4], state[5]);
    state[4] = AES_ENC(state[3], state[4]);
    state[3] = AES_ENC(state[2], state[3]);
    state[2] = AES_ENC(state[1], state[2]);
    state[1] = AES_ENC(state[0], state[1]);
    state[0] = AES_ENC(tmp, state[0]);

    state[0] = AES_BLOCK_XOR(state[0], d1);
    state[4] = AES_BLOCK_XOR(state[4], d2);
}

static void
crypto_aead_aegis128l_init(const unsigned char *key, const unsigned char *nonce,
                           aes_block_t *const state)
{
    static CRYPTO_ALIGN(16)
        const uint8_t c0_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    static CRYPTO_ALIGN(16)
        const uint8_t c1_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    const aes_block_t c0    = AES_BLOCK_LOAD(c0_);
    const aes_block_t c1    = AES_BLOCK_LOAD(c1_);
    aes_block_t       k;
    aes_block_t       n;
    int               i;

    k = AES_BLOCK_LOAD(key);
    n = AES_BLOCK_LOAD(nonce);

    state[0] = AES_BLOCK_XOR(k, n);
    state[1] = c0;
    state[2] = c1;
    state[3] = c0;
    state[4] = AES_BLOCK_XOR(k, n);
    state[5] = AES_BLOCK_XOR(k, c1);
    state[6] = AES_BLOCK_XOR(k, c0);
    state[7] = AES_BLOCK_XOR(k, c1);
    for (i = 0; i < 10; i++) {
        crypto_aead_aegis128l_update(state, n, k);
    }
}

static void
crypto_aead_aegis128l_mac(unsigned char *mac, size_t adlen, size_t mlen, aes_block_t *const state)
{
    aes_block_t tmp;
    int         i;

    tmp = AES_BLOCK_LOAD_64x2(mlen << 3, adlen << 3);
    tmp = AES_BLOCK_XOR(tmp, state[2]);

    for (i = 0; i < 7; i++) {
        crypto_aead_aegis128l_update(state, tmp, tmp);
    }

    tmp = AES_BLOCK_XOR(state[6], state[5]);
    tmp = AES_BLOCK_XOR(tmp, state[4]);
    tmp = AES_BLOCK_XOR(tmp, state[3]);
    tmp = AES_BLOCK_XOR(tmp, state[2]);
    tmp = AES_BLOCK_XOR(tmp, state[1]);
    tmp = AES_BLOCK_XOR(tmp, state[0]);

    AES_BLOCK_STORE(mac, tmp);
}

static inline void
crypto_aead_aegis128l_absorb(const unsigned char *const src, aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + 16);
    crypto_aead_aegis128l_update(state, msg0, msg1);
}

static void
crypto_aead_aegis128l_enc(unsigned char *const dst, const unsigned char *const src,
                          aes_block_t *const state)
{
    aes_block_t msg0, msg1;
    aes_block_t tmp0, tmp1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + 16);
    tmp0 = AES_BLOCK_XOR(msg0, state[6]);
    tmp0 = AES_BLOCK_XOR(tmp0, state[1]);
    tmp1 = AES_BLOCK_XOR(msg1, state[2]);
    tmp1 = AES_BLOCK_XOR(tmp1, state[5]);
    tmp0 = AES_BLOCK_XOR(tmp0, AES_BLOCK_AND(state[2], state[3]));
    tmp1 = AES_BLOCK_XOR(tmp1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, tmp0);
    AES_BLOCK_STORE(dst + 16, tmp1);

    crypto_aead_aegis128l_update(state, msg0, msg1);
}

static void
crypto_aead_aegis128l_dec(unsigned char *const dst, const unsigned char *const src,
                          aes_block_t *const state)
{
    aes_block_t msg0, msg1;

    msg0 = AES_BLOCK_LOAD(src);
    msg1 = AES_BLOCK_LOAD(src + 16);
    msg0 = AES_BLOCK_XOR(msg0, state[6]);
    msg0 = AES_BLOCK_XOR(msg0, state[1]);
    msg1 = AES_BLOCK_XOR(msg1, state[2]);
    msg1 = AES_BLOCK_XOR(msg1, state[5]);
    msg0 = AES_BLOCK_XOR(msg0, AES_BLOCK_AND(state[2], state[3]));
    msg1 = AES_BLOCK_XOR(msg1, AES_BLOCK_AND(state[6], state[7]));
    AES_BLOCK_STORE(dst, msg0);
    AES_BLOCK_STORE(dst + 16, msg1);

    crypto_aead_aegis128l_update(state, msg0, msg1);
}

int
crypto_aead_aegis128l_encrypt_detached(unsigned char *c, unsigned char *mac, const unsigned char *m,
                                       size_t mlen, const unsigned char *ad, size_t adlen,
                                       const unsigned char *npub, const unsigned char *k)
{
    aes_block_t state[8];
    CRYPTO_ALIGN(16)
    unsigned char src[32];
    CRYPTO_ALIGN(16)
    unsigned char dst[32];
    size_t        i;

    crypto_aead_aegis128l_init(k, npub, state);

    for (i = 0ULL; i + 32ULL <= adlen; i += 32ULL) {
        crypto_aead_aegis128l_absorb(ad + i, state);
    }
    if (adlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, ad + i, adlen & 0x1f);
        crypto_aead_aegis128l_absorb(src, state);
    }
    for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
        crypto_aead_aegis128l_enc(c + i, m + i, state);
    }
    if (mlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, m + i, mlen & 0x1f);
        crypto_aead_aegis128l_enc(dst, src, state);
        memcpy(c + i, dst, mlen & 0x1f);
    }

    crypto_aead_aegis128l_mac(mac, adlen, mlen, state);

    return 0;
}

int
crypto_aead_aegis128l_encrypt(unsigned char *c, const unsigned char *m, size_t mlen,
                              const unsigned char *ad, size_t adlen, const unsigned char *npub,
                              const unsigned char *k)
{
    return crypto_aead_aegis128l_encrypt_detached(c, c + mlen, m, mlen, ad, adlen, npub, k);
}

int
crypto_aead_aegis128l_decrypt_detached(unsigned char *m, const unsigned char *c, size_t clen,
                                       const unsigned char *mac, const unsigned char *ad,
                                       size_t adlen, const unsigned char *npub,
                                       const unsigned char *k)
{
    aes_block_t state[8];
    CRYPTO_ALIGN(16)
    unsigned char src[32];
    CRYPTO_ALIGN(16)
    unsigned char dst[32];
    CRYPTO_ALIGN(16)
    unsigned char computed_mac[16];
    size_t        i;
    size_t        mlen;
    unsigned char d;

    mlen = clen;
    crypto_aead_aegis128l_init(k, npub, state);

    for (i = 0ULL; i + 32ULL <= adlen; i += 32ULL) {
        crypto_aead_aegis128l_absorb(ad + i, state);
    }
    if (adlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, ad + i, adlen & 0x1f);
        crypto_aead_aegis128l_absorb(src, state);
    }
    if (m != NULL) {
        for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
            crypto_aead_aegis128l_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
            crypto_aead_aegis128l_dec(dst, c + i, state);
        }
    }
    if (mlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, c + i, mlen & 0x1f);
        crypto_aead_aegis128l_dec(dst, src, state);
        if (m != NULL) {
            memcpy(m + i, dst, mlen & 0x1f);
        }
        memset(dst, 0, mlen & 0x1f);
        state[0] = AES_BLOCK_XOR(state[0], AES_BLOCK_LOAD(dst));
        state[4] = AES_BLOCK_XOR(state[4], AES_BLOCK_LOAD(dst + 16));
    }

    crypto_aead_aegis128l_mac(computed_mac, adlen, mlen, state);
    d = 0;
    for (i = 0; i < 16; i++) {
        d |= computed_mac[i] ^ mac[i];
    }
    if (d != 0) {
        memset(m, 0, mlen);
        return -1;
    }
    return 0;
}

int
crypto_aead_aegis128l_decrypt(unsigned char *m, const unsigned char *c, size_t clen,
                              const unsigned char *ad, size_t adlen, const unsigned char *npub,
                              const unsigned char *k)
{
    int ret = -1;

    if (clen >= 16ULL) {
        ret = crypto_aead_aegis128l_decrypt_detached(m, c, clen - 16ULL, c + clen - 16ULL, ad,
                                                     adlen, npub, k);
    }
    return ret;
}
