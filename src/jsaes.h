#ifndef _JSAES_H_
#define _JSAES_H_

extern unsigned char *encrypt(const char *source, const char *passwd, int *crypted_len);
extern char *decrypt(unsigned char *crypted, int crypted_len, const char *passwd, int *decrypted_len);

int counter_encrypt_or_decrypt (char *passwd,
                                char *pt,  /* a buffer containing the data to be encrypted or decrypted */
                                char *ct,  /* a buffer that will contain the crypted or encrypted data */
                                int len,   /* the number of bytes from the input buffer, pt, to process */
                                unsigned char *counter);



#endif /* _JSAES_H_ */
