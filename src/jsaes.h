#ifndef _JSAES_H_
#define _JSAES_H_

extern unsigned char *encrypt(const char *source, const char *passwd, int *crypted_len);
extern char *decrypt(unsigned char *crypted, int crypted_len, const char *passwd, int *decrypted_len);



#endif /* _JSAES_H_ */
