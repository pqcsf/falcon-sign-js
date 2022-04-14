/*
 * Encoding/decoding of keys and signatures.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2022  Falcon JS(WASM) API
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author  PQCSF
 */

#include "inner.h"
#define NONCELEN 40
#define SEEDLEN 48

#if FALCON == 1024
#define CRYPTO_SECRETKEYBYTES   2305
#define CRYPTO_PUBLICKEYBYTES   1793
#define CRYPTO_BYTES            1330
#define CRYPTO_ALGNAME          "Falcon-1024"
#define FALCONLEN 				1024
#define FALCONLOGLEN 			10
#define FALCON_KEYGEN_TEMP FALCON_KEYGEN_TEMP_10
#else
#define CRYPTO_SECRETKEYBYTES   1281
#define CRYPTO_PUBLICKEYBYTES   897
#define CRYPTO_BYTES            690
#define CRYPTO_ALGNAME          "Falcon-512"
#define FALCONLEN 				512
#define FALCONLOGLEN 			9
#define FALCON_KEYGEN_TEMP FALCON_KEYGEN_TEMP_9
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool falconGenkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk);
bool falconPublicKeyCreate(const uint8_t *sk, uint8_t *pk);
bool falconSign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt);
bool falconVerify(uint8_t *sm, uint8_t *m, const uint8_t *pk);

#ifdef __cplusplus
}
#endif