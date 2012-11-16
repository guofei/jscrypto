#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "jsrsa.h"

static void print_error(char *msg, unsigned long err);
static int write_public_key(const char *path, RSA *key);
static int write_private_key(const char *path, RSA *key);
static char* str_join(const char* a, const char* b);

KEYS keys;

int pass_cb1(char *buf, int size, int rwflag, void *u)
{
        int len;
        char *tmp;
        /* We'd probably do something else if 'rwflag' is 1 */
        printf("Enter pass phrase for \"%s\"\n", (char *)u);
        /* get pass phrase, length 'len' into 'tmp' */
        tmp = "12345678";
        len = strlen(tmp);
        if (len <= 0) return 0;
        /* if too long, truncate */
        if (len > size) len = size;
        memcpy(buf, tmp, len);
        return len;
}

RSA *read_rsa_key_from_file(const char *file, KeyType type)
{
        FILE *fp = fopen(file, "r");
        if(fp == NULL){
                perror(file);
                return NULL;
        }
        OpenSSL_add_all_algorithms();
        RSA *key;

        if(type == PUBLIC_KEY)
                key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        else if(type == PRIVATE_KEY)
                key = PEM_read_RSAPrivateKey(fp, NULL, pass_cb1, "My Private Key");

        fclose(fp);

        if(key == NULL){
                fprintf(stderr, "failed to read key");
                return NULL;
        }

        return key;
}

void free_rsa_key(RSA *key)
{
        RSA_free(key);
}

int generate_rsa_key_to_file(const char *path, int size)
{
        RSA *key = RSA_generate_key(size, 65537, NULL, NULL);
        if(key == NULL){
                print_error("generate key", ERR_get_error());
                return -1;
        }

        if(write_public_key(path, key) < 0)
                return -1;

        if(write_private_key(path, key) < 0)
                return -1;

        RSA_free(key);

        return 0;
}

char* public_encrypt(RSA *key, const char *from, int from_len)
{
        BIO *plaintext_mem = BIO_new_mem_buf(from, from_len);

        BIO *ciphertext_mem = BIO_new(BIO_s_mem());
        BIO *bio_base64 = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
        BIO *bio_chain = BIO_push(bio_base64, ciphertext_mem);

        int rsa_size = RSA_size(key);
        char *inbuf = malloc(rsa_size);
        char *outbuf = malloc(rsa_size);
        while(1){
                int read_size = rsa_size - 11;
                int inlen = BIO_read(plaintext_mem, inbuf, read_size);
                if(inlen <= 0)
                        break;

                memset(outbuf, 0, rsa_size);

                int outlen;
                if((outlen = RSA_public_encrypt(inlen, (void *)inbuf, (void *)outbuf, key, RSA_PKCS1_PADDING)) == -1){
                        print_error("failed to RSA_public_encrypt", ERR_get_error());
                        exit(-1);
                }

                int len = BIO_write(bio_chain, outbuf, outlen);
		if(len < outlen){
			print_error("failed to BIO_write", ERR_get_error());
                        exit(-1);
		}
        }
        BIO_flush(bio_chain);
        free(inbuf);
        free(outbuf);
        BIO_free(plaintext_mem);

        char *ciphertext = NULL;
        while(1){
                int read_size = 512;
                char *buf = calloc(read_size + 1, sizeof(char));
                int len = BIO_read(ciphertext_mem, buf, read_size);
                if(len <= 0)
                        break;
                ciphertext = str_join(ciphertext, buf);
        }
        BIO_free_all(bio_chain);

        return ciphertext;
}

char* private_decrypt(RSA *key, const char *from, int from_len)
{
        BIO *bio_base64 = BIO_new(BIO_f_base64());
        BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
        BIO *mem_buf = BIO_new_mem_buf(from, from_len);
        mem_buf = BIO_push(bio_base64, mem_buf);

        BIO *plaintext_mem = BIO_new(BIO_s_mem());
        int plaintext_len = 0;
        int rsa_size = RSA_size(key);

        char *inbuf = malloc(rsa_size);
        char *outbuf = malloc(rsa_size);
        while(1){
                int read_size = rsa_size;
                int inlen = BIO_read(mem_buf, inbuf, read_size);
                if(inlen <= 0)
                        break;

                memset(outbuf, 0, rsa_size);

                int outlen;
                if((outlen = RSA_private_decrypt(inlen, (void *)inbuf, (void *)outbuf, key, RSA_PKCS1_PADDING)) == -1){
                        print_error("failed to RSA_private_decrypt", ERR_get_error());
                        exit(-1);
                }
                int len = BIO_write(plaintext_mem, outbuf, outlen);
                plaintext_len += len;
        }
        BIO_flush(plaintext_mem);
        free(inbuf);
        free(outbuf);
        BIO_free_all(mem_buf);

        char *plaintext = NULL;
        while(1){
                int read_size = 512;
                char *buf = calloc(read_size + 1, sizeof(char));
                int len = BIO_read(plaintext_mem, buf, read_size);
                if(len <= 0)
                        break;
                plaintext = str_join(plaintext, buf);
        }
        BIO_free(plaintext_mem);

        return plaintext;
}

static void print_error(char *msg, unsigned long err)
{
        char *errmsg = ERR_error_string(err, NULL);
        fprintf(stderr, "%s(%s)\n", msg, errmsg);
}

static char* str_join(const char* a, const char* b)
{
        if(a == NULL && b == NULL)
                return NULL;

        size_t la = 0;
        if(a)
                la = strlen(a);

        size_t lb = 0;
        if(b)
                lb = strlen(b);

        char* p = malloc(la + lb + 1);
        memcpy(p, a, la);
        memcpy(p + la, b, lb + 1);
        return p;
}

static int write_public_key(const char *path, RSA *key)
{
        char *pubkey_name = str_join(path, "/public.pem");
        FILE *pubkey = fopen(pubkey_name, "w");
        if(pubkey == NULL){
                perror(pubkey_name);
                return -1;
        }
        if(PEM_write_RSAPublicKey(pubkey, key) != 1){
                print_error("write rsa public key err", ERR_get_error());
                return -1;
        }
        free(pubkey_name);
        fclose(pubkey);

        return 0;
}

int pass_cb2(char *buf, int size, int rwflag, void *u)
{
        int len;
        char *tmp;
        /* We'd probably do something else if 'rwflag' is 1 */
        printf("Enter pass phrase for \"%s\"\n", (char *)u);
        /* get pass phrase, length 'len' into 'tmp' */
        tmp = "hello";
        //len = strlen(tmp);
        len = 5;
        if (len <= 0) return 0;
        /* if too long, truncate */
        if (len > size) len = size;
        memcpy(buf, tmp, len);
        return len;
}

static int write_private_key(const char *path, RSA *key)
{
        char *seckey_name = str_join(path, "/private.pem");
        FILE *seckey = fopen(seckey_name, "w");
        if(seckey == NULL){
                perror(seckey_name);
                return -1;
        }
        if(PEM_write_RSAPrivateKey(seckey, key, EVP_des_ede3_cbc(), (unsigned char *)"12345678", 8, NULL, NULL) != 1){
                print_error("write rsa private key err", ERR_get_error());
                return -1;
        }
        free(seckey_name);
        fclose(seckey);

        return 0;
}

int test(int test){
        return 0;
}

char *unbase64(unsigned char *input, int length)
{
        BIO *b64, *bmem;

        char *buffer = (char *)malloc(length);
        memset(buffer, 0, length);

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bmem = BIO_new_mem_buf(input, length);
        bmem = BIO_push(b64, bmem);

        BIO_read(bmem, buffer, length);

        BIO_free_all(bmem);

        return buffer;
}
