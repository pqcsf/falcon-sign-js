#define NONCELEN 40
#define SEEDLEN 48

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