#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "ems.h"

#if FALCON == 1024
#include "falcon1024/api.h"
#else
#include "falcon512/api.h"
#endif

EM_PORT_API(uint32_t) getSkByte() 
{
	return CRYPTO_SECRETKEYBYTES;
}

EM_PORT_API(uint32_t) getPkByte() 
{
	return CRYPTO_PUBLICKEYBYTES;
}

EM_PORT_API(uint32_t) getCryptoByte()
{
	return CRYPTO_BYTES;
}

EM_PORT_API(uint32_t) getGenKeySeedByte()
{
	return SEEDLEN;
}

EM_PORT_API(uint32_t) getCryptoNonceByte()
{
	return NONCELEN;
}

EM_PORT_API(uint32_t) getCryptoSaltByte()
{
	return NONCELEN + SEEDLEN;
}

EM_PORT_API(bool) genkey(uint8_t *genKeySeed, uint8_t *pk, uint8_t *sk)
{   
    return falconGenkey(genKeySeed, pk, sk);
}

EM_PORT_API(bool) publicKeyCreate(const uint8_t *sk, uint8_t *pk)
{
	return falconPublicKeyCreate(sk, pk);
}

EM_PORT_API(bool) sign(uint8_t *sm, uint8_t *m, const uint8_t *sk, uint8_t *salt)
{   
    return falconSign(sm, m, sk, salt);
}

EM_PORT_API(bool) verify(uint8_t *sm, uint8_t *m, const uint8_t *pk)
{   
    return falconVerify(sm, m, pk);
}

EM_PORT_API(uint8_t*) newByte(uint64_t length)
{
    return (uint8_t*)malloc(length * sizeof(uint8_t));
}

EM_PORT_API(void) freeBuf(uint8_t* ptr)
{
    free(ptr);
}

EM_PORT_API(void) freeBufSafe(uint8_t* ptr, uint64_t length)
{
	memset(ptr, 0, length);
    free(ptr);
}