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
	//char *t = "Hello world";
	char *t = calloc(10, sizeof(char));
	t[0] = 1;
	t[3] = 22;
	t[5] = 33;
	base64_encode(t, 10, &base64EncodeOutput);
	printf("Output (base64): %s\n", base64EncodeOutput);

	char* base64DecodeOutput;
	int b64_l = base64_decode(base64EncodeOutput, &base64DecodeOutput);
	printf("Output: %s\n", base64DecodeOutput);
	
	// test jsrsa
	unsigned char tt[] = "abc";

	generate_rsa_key_to_file("./", 1024, "12345678");

	RSA *pub = read_rsa_key_from_file("./public.pem", PUBLIC_KEY, NULL);
	RSA *pri = read_rsa_key_from_file("./private.pem", PRIVATE_KEY, "12345678");

	unsigned char *text = public_encrypt(pub, tt, strlen(tt)*sizeof(tt[0]));

	FILE *outFile = fopen("out.txt", "w");
	fwrite(text, 1, strlen(text)*sizeof(text[0]), outFile);
	fclose(outFile);

	char *text2 = private_decrypt(pri, text, strlen(text)*sizeof(text[0]));
	printf ("%s\n",text2);

	// test jsaes
	EVP_CIPHER_CTX *ctx = cipher_ctx_new("password");

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

	char *text11, *text22;
	counter_encrypt("password", "0123456789", &text11, 10, counter);
	counter_decrypt("password", text11, &text22, 10, counter2);
	printf ("%s\n",text22);
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
