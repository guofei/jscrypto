#ifndef _JSASR_H_
#define _JSASR_H_

#include <openssl/rsa.h>

typedef struct {
        RSA *my_private;
        RSA *my_public;
        RSA **publics;
        char **key_ids;
        char **key_path;
        size_t n_public;
}KEYS;

typedef enum { PRIVATE_KEY , PUBLIC_KEY } KeyType;

extern int test(int test);
extern int generate_rsa_key_to_file(const char *path, int size, const char *password);
extern RSA* read_rsa_key_from_file(const char *file, KeyType type, const char *password);
extern void free_rsa_key(RSA *key);
extern char* public_encrypt(RSA *key, const char *from, int data_len);
extern char* private_decrypt(RSA *key, const char *from, int data_len);

#endif /* _JSASR_H_ */
