#include <stdio.h>
#include <string.h>

#include "../src/jsrsa.h"

int main(int argc, char **argv)
{
  unsigned char tt[] = "abc";

  generate_rsa_key_to_file("./", 1024, "12345678");

  RSA *pub = read_rsa_key_from_file("./public.pem", PUBLIC_KEY, NULL);
  RSA *pri = read_rsa_key_from_file("./private.pem", PRIVATE_KEY, "12345678");

  Keys k = keys_new();
  keys_push(k, pub);
  keys_push(k, pri);

  unsigned char *text = public_encrypt(keys_get(k, 0), tt, strlen(tt)*sizeof(tt[0]));

  FILE *outFile = fopen("out.txt", "w");
  fwrite(text, 1, strlen(text)*sizeof(text[0]), outFile);
  fclose(outFile);

  char *text2 = private_decrypt(keys_get(k, 1), text, strlen(text)*sizeof(text[0]));
  printf ("%s\n",text2);

  keys_free(k);

  return 0;
}
