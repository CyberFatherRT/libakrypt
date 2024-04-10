#include <libakrypt-base.h>
#include <libakrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    m_cbc,
    m_ctr,
    m_ofb,
    m_cfb,
    m_ecb,
} Mode;

typedef struct {
    char *algorithm;
    char *input;
    char *output;
    ak_uint8 *key;
    size_t key_size;
    ak_uint8 *iv;
    size_t iv_size;
    Mode mode;
} Config;

int akrypt_encrypt(const Config *config) {

    struct bckey ctx;

    char *algorithm = config->algorithm;
    char *output = config->output;
    char *input = config->input;
    ak_uint8 *key = config->key;
    size_t key_size = config->key_size;
    ak_uint8 *iv = config->iv;
    size_t iv_size = config->iv_size;
    Mode mode = config->mode;

    int error = ak_error_ok;
    int exitstatus = EXIT_FAILURE;

    if (!ak_libakrypt_create(ak_function_log_stderr)) {
        return ak_libakrypt_destroy();
    }

    if (strcmp(algorithm, "kuznyechik") == 0) {
        ak_bckey_create_kuznechik(&ctx);
    } else if (strcmp(algorithm, "magma") == 0) {
        ak_bckey_create_magma(&ctx);
    } else {
        char *err_msg = malloc((20 + strlen(algorithm)) * sizeof(char));
        sprintf(err_msg, "Unknown algorithm: %s", algorithm);
        ak_log_set_message(err_msg);
        free(err_msg);
        return 1;
    }

    ak_bckey_set_key(&ctx, key, key_size);

    switch (mode) {
    case m_cbc:
        error = ak_bckey_encrypt_cbc(&ctx, input, output, strlen(input), iv,
                                     iv_size);
        if (error != ak_error_ok)
            goto exlab;
        break;
    case m_ctr:
        error = ak_bckey_ctr(&ctx, input, output, strlen(input), iv, iv_size);
        if (error != ak_error_ok)
            goto exlab;
        break;
    case m_ofb:
        error = ak_bckey_ofb(&ctx, input, output, strlen(input), iv, iv_size);
        if (error != ak_error_ok)
            goto exlab;
        break;
    case m_cfb:
        error = ak_bckey_encrypt_cfb(&ctx, input, output, strlen(input), iv,
                                     iv_size);
        if (error != ak_error_ok)
            goto exlab;
        break;
    case m_ecb:
        error = ak_bckey_encrypt_ecb(&ctx, input, output, strlen(input));
        if (error != ak_error_ok)
            goto exlab;
        break;
    }

    strcpy(output, ak_ptr_to_hexstr(output, strlen(input), ak_false));

exlab:
    ak_bckey_destroy(&ctx);

    if (error == ak_error_ok)
        exitstatus = EXIT_SUCCESS;

    ak_libakrypt_destroy();

    return exitstatus;
}

int akrypt_decrypt(const Config *config) {

    struct bckey ctx;

    char *algorithm = config->algorithm;
    char *output = config->output;
    char *input = config->input;
    ak_uint8 *key = config->key;
    size_t key_size = config->key_size;
    ak_uint8 *iv = config->iv;
    size_t iv_size = config->iv_size;
    Mode mode = config->mode;

    int error = ak_error_ok;
    int exitstatus = EXIT_FAILURE;

    if (!ak_libakrypt_create(ak_function_log_stderr)) {
        return ak_libakrypt_destroy();
    }

    if (strcmp(algorithm, "kuznyechik") == 0) {
        ak_bckey_create_kuznechik(&ctx);
    } else if (strcmp(algorithm, "magma") == 0) {
        ak_bckey_create_magma(&ctx);
    } else {
        char *err_msg = malloc((20 + strlen(algorithm)) * sizeof(char));
        sprintf(err_msg, "Unknown algorithm: %s", algorithm);
        ak_log_set_message(err_msg);
        free(err_msg);
        return 1;
    }

    ak_bckey_set_key(&ctx, key, key_size);

    switch (mode) {
    case m_cbc:
        error = ak_bckey_decrypt_cbc(&ctx, input, output, strlen(input), iv,
                                     iv_size);
        break;
    case m_ctr:
        error = ak_bckey_ctr(&ctx, input, output, strlen(input), iv, iv_size);
        break;
    case m_ofb:
        error = ak_bckey_ofb(&ctx, input, output, strlen(input), iv, iv_size);
        break;
    case m_cfb:
        error = ak_bckey_decrypt_cfb(&ctx, input, output, strlen(input), iv,
                                     iv_size);
        break;
    case m_ecb:
        error = ak_bckey_decrypt_ecb(&ctx, input, output, strlen(input));
        break;
    }

    ak_bckey_destroy(&ctx);

    if (error == ak_error_ok)
        exitstatus = EXIT_SUCCESS;

    ak_libakrypt_destroy();

    return exitstatus;
}
