#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEYGEN_SALT  NULL
#define KEYGEN_COUNT 2048

EVP_CIPHER_CTX *cipher_ctx_new(char *passwd)
{
        EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));
        const EVP_CIPHER *cipher = EVP_aes_256_ecb();
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

        EVP_CIPHER_CTX_init(ctx);

        // passphrase -> key, iv
        if (EVP_BytesToKey(cipher, EVP_md5(), KEYGEN_SALT, passwd, strlen(passwd), KEYGEN_COUNT, key, iv) < 1) {
                fprintf(stderr, "EVP_BytesToKey: failure\n");
                exit(1);
        }

        if (EVP_CipherInit(ctx, cipher, key, iv, 1) != 1) {
                fprintf(stderr, "EVP_CipherInit: failure\n");
        }
	return ctx;
}

void cipher_ctx_free(EVP_CIPHER_CTX *ctx)
{
	free(ctx);
}

unsigned char *counter_new(int i, EVP_CIPHER_CTX *ctx)
{
	unsigned char *counter = calloc(EVP_CIPHER_CTX_block_size(ctx), sizeof(unsigned char));
	memcpy(counter, &i, sizeof(int));
	return counter;
}

void counter_free(unsigned char *counter)
{
	free(counter);
}

int counter_encrypt_or_decrypt (EVP_CIPHER_CTX *ctx,
                                char *pt,  /* a buffer containing the data to be encrypted or decrypted */
                                char *ct,  /* a buffer that will contain the crypted or encrypted data */
                                int len,   /* the number of bytes from the input buffer, pt, to process */
                                unsigned char *counter)
{
        int i, j, where = 0, num, bl = EVP_CIPHER_CTX_block_size (ctx);
        char encr_ctrs[len + bl];/* Encrypted counters. */

        if (EVP_CIPHER_CTX_mode (ctx) != EVP_CIPH_ECB_MODE)
                return -1;
        /* <= is correct, so that we handle any possible non-aligned data. */
        for (i = 0; i <= len / bl; i++)
        {
                /* Encrypt the current counter. */
                EVP_EncryptUpdate (ctx, &encr_ctrs[where], &num, counter, bl);
                where += num;
                /* Increment the counter. Remember it's an array of single characters */
                for (j = 0; j < bl / sizeof (char); j++)
                {
                        if (++counter[j])
                                break;
                }
        }
        /* XOR the key stream with the first buffer, placing the results in the
         * second buffer.
         */
        for (i = 0; i < len; i++)
                ct[i] = pt[i] ^ encr_ctrs[i];

        /* Success. */
        return 1;
}


static void print_hexstring(unsigned char *data, int datal) {
        int i;

        for (i = 0; i < datal; i++) {
                printf("%02x", data[i]);
        }
}

unsigned char *encrypt(const char *source, const char *passwd, int *crypted_len)
{
        EVP_CIPHER_CTX ctx;
        const EVP_CIPHER *cipher = EVP_aes_256_ecb();
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
        unsigned char *crypted;
        int source_len, tail_len;

        EVP_CIPHER_CTX_init(&ctx);

        // passphrase -> key, iv
        if (EVP_BytesToKey(cipher, EVP_md5(), KEYGEN_SALT, passwd, strlen(passwd), KEYGEN_COUNT, key, iv) < 1) {
                fprintf(stderr, "EVP_BytesToKey: failure\n");
                exit(1);
        }

        printf("key: ");
        print_hexstring(key, EVP_MAX_KEY_LENGTH);
        printf("\n");

        if (EVP_CipherInit(&ctx, cipher, key, iv, 1) != 1) {
                fprintf(stderr, "EVP_CipherInit: failure\n");
        }

        source_len = strlen(source);
        crypted = (unsigned char *) malloc(source_len + EVP_CIPHER_block_size(cipher) * 2 + 1);

        if (EVP_CipherUpdate(&ctx, crypted, crypted_len, source, source_len) != 1) {
                fprintf(stderr, "EVP_CipherUpdate: failure\n");
                exit(1);
        }

        if (EVP_CipherFinal(&ctx, (crypted + *crypted_len), &tail_len) != 1) {
                fprintf(stderr, "EVP_CipherFinal: failure\n");
                exit(1);
        }

        if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
                fprintf(stderr, "EVP_CIPHER_CTX_cleanup: failure\n");
                exit(1);
        }

        *crypted_len += tail_len;

        return crypted;
}

char *decrypt(unsigned char *crypted, int crypted_len, const char *passwd, int *decrypted_len)
{
        EVP_CIPHER_CTX ctx;
        const EVP_CIPHER *cipher = EVP_aes_256_ecb();
        unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
        unsigned char *decrypted;
        int tail_len;

        EVP_CIPHER_CTX_init(&ctx);

        // passphrase -> key, iv
        if (EVP_BytesToKey(cipher, EVP_md5(), KEYGEN_SALT, passwd, strlen(passwd), KEYGEN_COUNT, key, iv) < 1) {
                fprintf(stderr, "EVP_BytesToKey: failure\n");
                exit(1);
        }

        if (EVP_CipherInit(&ctx, cipher, key, iv, 0) != 1) {
                fprintf(stderr, "EVP_CipherInit: failure\n");
        }

        decrypted = (unsigned char *) malloc(crypted_len + EVP_CIPHER_block_size(cipher) * 2 + 1);

        if (EVP_CipherUpdate(&ctx, decrypted, decrypted_len, crypted, crypted_len) != 1) {
                fprintf(stderr, "EVP_CipherUpdate: failure\n");
                exit(1);
        }

        if (EVP_CipherFinal(&ctx, (decrypted + *decrypted_len), &tail_len) != 1) {
                fprintf(stderr, "EVP_CipherFinal: failure\n");
                exit(1);
        }

        if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
                fprintf(stderr, "EVP_CIPHER_CTX_cleanup: failure\n");
                exit(1);
        }

        *decrypted_len += tail_len;
        decrypted[*decrypted_len] = 0;

        return decrypted;
}
