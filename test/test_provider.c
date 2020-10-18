#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

int main()
{
	OPENSSL_CTX *ctx;
	OSSL_PROVIDER *prov = NULL;
	EVP_MD *md = NULL;
	int res = 0;

	ctx = OPENSSL_CTX_new();
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	prov = OSSL_PROVIDER_load(ctx, "blake3");
	if (!prov) {
		ERR_print_errors_fp(stderr);

		OPENSSL_CTX_free(ctx);
		return 1;
	}

	md = EVP_MD_fetch(ctx, "blake3", NULL);
	if (!md) {
		ERR_print_errors_fp(stderr);

		OSSL_PROVIDER_unload(prov);
		OPENSSL_CTX_free(ctx);
		return 1;
	}

	EVP_MD_free(md);
	OSSL_PROVIDER_unload(prov);
	OPENSSL_CTX_free(ctx);

	printf("Success!\n");
	return 0;
}