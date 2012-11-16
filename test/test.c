#include <stdio.h>
#include <string.h>

#include "../src/jsrsa.h"

int main(int argc, char **argv)
{
  unsigned char tt[] = "abc";

  generate_rsa_key_to_file("./", 1024);

  RSA *pub = read_rsa_key_from_file("./public.pem", PUBLIC_KEY);
  RSA *pri = read_rsa_key_from_file("./private.pem", PRIVATE_KEY);

  unsigned char *text = public_encrypt(pub, tt, strlen(tt)*sizeof(tt[0]));

  FILE *outFile = fopen("out.txt", "w");
  fwrite(text, 1, strlen(text)*sizeof(text[0]), outFile);
  fclose(outFile);

  char *text2 = private_decrypt(pri, text, strlen(text)*sizeof(text[0]));

  return 0;
}
