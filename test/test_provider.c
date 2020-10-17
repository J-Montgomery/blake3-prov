#include <stdio.h>
#include <openssl/core.h>
#include <openssl/provider.h>

int main()
{
	OSSL_LIB_CTX *ctx;
	EVP_MD *md = NULL;
	int res = 0;

	ctx = OSSL_LIB_CTX_new();
	if (!ctx) {
		printf("ctx NULL\n");
		return 1;
	}

	md = EVP_MD_fetch(ctx, "blake3", NULL));
	if (!md) {
		printf("Digest NULL\n");
		return 1;
	}

	printf("Success!\n");
	return 0;
}