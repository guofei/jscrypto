#ifndef _JSAES_H_
#define _JSAES_H_

extern EVP_CIPHER_CTX *cipher_ctx_new(char *passwd);
extern void cipher_ctx_free(EVP_CIPHER_CTX *ctx);

extern unsigned char *counter_new(int i, EVP_CIPHER_CTX *ctx);
extern void counter_free(unsigned char *counter);

extern int counter_encrypt_or_decrypt (EVP_CIPHER_CTX *ctx,
                                char *pt,  /* a buffer containing the data to be encrypted or decrypted */
                                char *ct,  /* a buffer that will contain the crypted or encrypted data */
                                int len,   /* the number of bytes from the input buffer, pt, to process */
                                unsigned char *counter);



/* not be used */
extern unsigned char *encrypt(const char *source, const char *passwd, int *crypted_len);
extern char *decrypt(unsigned char *crypted, int crypted_len, const char *passwd, int *decrypted_len);

#endif /* _JSAES_H_ */
