#ifndef _BASE64_H_
#define _BASE64_H_

extern int base64_encode(const char* message, int length, char** buffer);
extern int base64_calc_decode_length(const char* b64input);
extern int base64_decode(const char* b64message, char** buffer);

#endif /* _BASE64_H_ */
