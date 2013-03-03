#include <stdio.h>
#include <string.h>

#include "../src/jsrsa.h"
#include "../src/jsaes.h"
#include "../src/np_array.h"
#include "../src/base64.h"

int main(int argc, char **argv)
{
	// base64
	char* base64EncodeOutput;
	base64_encode("Hello World", &base64EncodeOutput);
	printf("Output (base64): %s\n", base64EncodeOutput);

	char* base64DecodeOutput;
	base64_decode("SGVsbG8gV29ybGQ=", &base64DecodeOutput);
	base64_calc_decode_length(base64EncodeOutput);
	printf("Output: %s\n", base64DecodeOutput);
	
	// test jsrsa
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

	// test jsaes
	EVP_CIPHER_CTX *ctx = cipher_ctx_new("123456");

	int n = 1000;
	char *pt = malloc(sizeof(char) * (n+1));
	for (int i = 0; i < n; ++i)
		pt[i] = 'a';
	pt[n] = 0;
	char *ct = calloc(n+1, sizeof(unsigned char));
	unsigned char *counter = counter_new(1, ctx);

	counter_encrypt_or_decrypt(ctx, pt, ct, n, counter);

	char *ct2 = calloc(n+1, sizeof(unsigned char));
	unsigned char *counter2 = counter_new(1, ctx);
	counter_encrypt_or_decrypt(ctx, ct, ct2, n, counter2);

	if(strcmp(pt, ct2) == 0)
		printf ("%s\n","counter encrypt ok");
	else
		printf ("%s\n","counter encrypt error");

	if(strcmp(counter, counter2) != 0)
		printf ("%s\n","counter error");


	// test nparray

	NP_Array array = NP_Array_new();
	EVP_CIPHER_CTX *elem1 = cipher_ctx_new("123456");
	EVP_CIPHER_CTX *elem2 = cipher_ctx_new("234567");
	int n1 = NP_Array_push(array, elem1);
	int n2 = NP_Array_push(array, elem2);
	EVP_CIPHER_CTX *elem3 = NP_Array_get(array, n1);
	NP_Array_free(array, cipher_ctx_free);
	return 0;
}
