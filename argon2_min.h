#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ARGON2_OK 0

int argon2id_hash_raw(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const void *pwd, size_t pwdlen, const void *salt, size_t saltlen,
    void *hash, size_t hashlen);

const char* argon2_error_message(int error_code);

#ifdef __cplusplus
}
#endif
