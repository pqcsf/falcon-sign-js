#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#if FALCON == 1024
#include "falcon1024/api.h"
#include "falcon1024/inner.h"
#define FALCONLEN 1024
#define FALCONLOGLEN 10
#define FALCON_KEYGEN_TEMP FALCON_KEYGEN_TEMP_10
#else
#include "falcon512/api.h"
#include "falcon512/inner.h"
#define FALCONLEN 512
#define FALCONLOGLEN 9
#define FALCON_KEYGEN_TEMP FALCON_KEYGEN_TEMP_9
#endif

#define TEMPALLOC
#define NONCELEN 40
#define SEEDLEN 48
#include <stdio.h>

static inline uint8_t * align_u16(void *tmp)
{
	uint8_t *atmp;

	atmp = tmp;
	if (((uintptr_t)atmp & 1u) != 0) {
		atmp ++;
	}
	return atmp;
}

/**
 * @param genKeySeed
 * @param pk
 * @param sk
 */
bool falconGenkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk)
{
	TEMPALLOC union
	{
		uint8_t b[FALCON_KEYGEN_TEMP];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;

	TEMPALLOC int8_t f[FALCONLEN], g[FALCONLEN], F[FALCONLEN];
	TEMPALLOC uint16_t h[FALCONLEN];
	TEMPALLOC inner_shake256_context rng;
	size_t u, v;

	/*
	 * Generate key pair.
	 */
	// randombytes(seed, sizeof seed);
	inner_shake256_init(&rng);
	inner_shake256_inject(&rng, genKeySeed, SEEDLEN);
	inner_shake256_flip(&rng);

	Zf(keygen)(&rng, f, g, F, NULL, h, FALCONLOGLEN, tmp.b);
	/*
	 * Encode private key.
	 */
	sk[0] = 0x50 + FALCONLOGLEN;
	
	u = 1;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u, f, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN]);
	if (v == 0) 
	{
		return 0;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u, g, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN]);
	if (v == 0) 
	{
		return 0;
	}
	u += v;
	v = Zf(trim_i8_encode)(sk + u, CRYPTO_SECRETKEYBYTES - u, F, FALCONLOGLEN, Zf(max_FG_bits)[FALCONLOGLEN]);
	if (v == 0)
	{
		return 0;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) 
	{
		return 0;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + FALCONLOGLEN;
	v = Zf(modq_encode)(pk + 1, CRYPTO_PUBLICKEYBYTES - 1, h, FALCONLOGLEN);
	if (v != CRYPTO_PUBLICKEYBYTES - 1) 
	{
		return 0; 
	}
	return 1;
}

#define FALCON_TMPSIZE_MAKEPUB(logn) ((6u << (logn)) + 1)

bool falconPublicKeyCreate(const uint8_t *sk, uint8_t *pk)
{
	uint8_t tmp[FALCON_TMPSIZE_MAKEPUB(FALCONLOGLEN)];
	uint8_t *atmp;
	size_t u, v, n;
	int8_t *f, *g;
	uint16_t *h;
	
	if(sk[0] != 0x50 + FALCONLOGLEN) 
	{
		return 0;
	}

	/*
	 * Decode private key (f and g).
	 */
	n = (size_t)1 << FALCONLOGLEN;
	f = (int8_t *)tmp;
	g = f + n;
	u = 1;
	v = Zf(trim_i8_decode)(f, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return 0;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN],
		sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) {
		return 0;
	}

	/*
	 * Compute public key.
	 */
	h = (uint16_t *)align_u16(g + n);
	atmp = (uint8_t *)(h + n);
	if (!Zf(compute_public)(h, f, g, FALCONLOGLEN, atmp)) 
	{
		return 0;
	}

	/*
	 * Encode public key.
	 */
	pk[0] = 0x00 + FALCONLOGLEN;
	v = Zf(modq_encode)(pk + 1, CRYPTO_PUBLICKEYBYTES - 1, h, FALCONLOGLEN);
	if (v != CRYPTO_PUBLICKEYBYTES - 1) 
	{
		return 0;
	}
	return 1;
}

bool falconSign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt)
{
	TEMPALLOC union 
	{
		uint8_t b[72 * FALCONLEN];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	TEMPALLOC int8_t f[FALCONLEN], g[FALCONLEN], F[FALCONLEN], G[FALCONLEN];
	TEMPALLOC union 
	{
		int16_t sig[FALCONLEN];
		uint16_t hm[FALCONLEN];
	} r;
	
	TEMPALLOC unsigned char* seed = salt;
	TEMPALLOC unsigned char* nonce = salt + SEEDLEN;
	TEMPALLOC unsigned char esig[CRYPTO_BYTES - 2 - NONCELEN];
	TEMPALLOC inner_shake256_context sc;
	size_t u, v, sig_len;

	//little-endian 8 byte
	uint64_t mlen = *((uint64_t*)m);
	m += 8;
	/*
	 * Decode the private key.
	 */
	if (sk[0] != 0x50 + FALCONLOGLEN) 
	{
		return 0;
	}
	u = 1;
	v = Zf(trim_i8_decode)(f, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN], sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) 
	{
		return 0;
	}
	u += v;
	v = Zf(trim_i8_decode)(g, FALCONLOGLEN, Zf(max_fg_bits)[FALCONLOGLEN], sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) 
	{
		return 0;
	}
	u += v;
	v = Zf(trim_i8_decode)(F, FALCONLOGLEN, Zf(max_FG_bits)[FALCONLOGLEN], sk + u, CRYPTO_SECRETKEYBYTES - u);
	if (v == 0) 
	{
		return 0;
	}
	u += v;
	if (u != CRYPTO_SECRETKEYBYTES) 
	{
		return 0;
	}
	if (!Zf(complete_private)(G, f, g, F, FALCONLOGLEN, tmp.b)) 
	{
		return 0;
	}

	/*
	 * Create a random nonce (40 bytes).
	 */
	// randombytes(nonce, NONCELEN); The random bytes are modified to be generated externally.

	/*
	 * Hash message nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, NONCELEN);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, r.hm, FALCONLOGLEN);

	/*
	 * Initialize a RNG.
	 */
	// randombytes(seed, sizeof seed); The random bytes are modified to be generated externally.
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, seed, SEEDLEN);
	inner_shake256_flip(&sc);
	
	/*
	 * Compute the signature.
	 */
	Zf(sign_dyn)(r.sig, &sc, f, g, F, G, r.hm, FALCONLOGLEN, tmp.b);

	/*
	 * Encode the signature and bundle it with the message. Format is:
	 *   signature length     2 bytes, big-endian = slen
	 *   nonce                40 bytes
	 *   signature            slen bytes
	 */
	esig[0] = 0x20 + FALCONLOGLEN;
	sig_len = Zf(comp_encode)(esig + 1, (sizeof esig) - 1, r.sig, FALCONLOGLEN);
	if (sig_len == 0) 
	{
		return 0;
	}
	sig_len ++;

	sm[0] = (uint8_t)(sig_len >> 8);
	sm[1] = (uint8_t)sig_len;
	memcpy(sm + 2, nonce, NONCELEN);
	memcpy(sm + 2 + NONCELEN, esig, sig_len);

	return 1;
}

bool falconVerify(uint8_t *sm, uint8_t *m, const uint8_t *pk)
{
	TEMPALLOC union 
	{
		uint8_t b[2 * FALCONLEN];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} tmp;
	const unsigned char *esig;
	TEMPALLOC uint16_t h[FALCONLEN], hm[FALCONLEN];
	TEMPALLOC int16_t sig[FALCONLEN];
	TEMPALLOC inner_shake256_context sc;
	uint16_t sig_len;

	//little-endian 8 byte
	uint64_t msg_len = *((uint64_t*)m);
	m += 8;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + FALCONLOGLEN) 
	{
		return 0;
	}
	if (Zf(modq_decode)(h, FALCONLOGLEN, pk + 1, CRYPTO_PUBLICKEYBYTES - 1) != CRYPTO_PUBLICKEYBYTES - 1)
	{
		return 0;
	}
	Zf(to_ntt_monty)(h, FALCONLOGLEN);

	/*
	 * Find nonce, signature, message length.
	 */
	sig_len = ((uint8_t)sm[0] << 8) | (uint8_t)sm[1];

	/*
	 * Decode signature.
	 */
	
	esig = sm + 2 + NONCELEN;
	if (sig_len < 1 || esig[0] != 0x20 + FALCONLOGLEN) 
	{
		return 0;
	}
	if (Zf(comp_decode)(sig, FALCONLOGLEN,esig + 1, sig_len - 1) != sig_len - 1)
	{
		return 0;
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, sm + 2, NONCELEN);
	inner_shake256_inject(&sc, m, msg_len);
	inner_shake256_flip(&sc);
	Zf(hash_to_point_vartime)(&sc, hm, FALCONLOGLEN);

	/*
	 * Verify signature.
	 */
	if (!Zf(verify_raw)(hm, sig, h, FALCONLOGLEN, tmp.b)) 
	{
		return 0;
	}

	return 1;
}

