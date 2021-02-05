#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

int main()
{
	OSSL_LIB_CTX *ctx;
	OSSL_PROVIDER *prov = NULL;
	EVP_MD *md = NULL;
	int ret = 0;

	ctx = OSSL_LIB_CTX_new();
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		ret = 1;
		goto exit;
	}

	prov = OSSL_PROVIDER_load(ctx, "blake3");
	if (!prov) {
		ERR_print_errors_fp(stderr);
		ret = 1;
		goto free_ctx;
	}

	md = EVP_MD_fetch(ctx, "blake3", NULL);
	if (!md) {
		ERR_print_errors_fp(stderr);
		ret = 1;
		goto prov_unload;
	}

	printf("Success!\n");

md_free:
	EVP_MD_free(md);
prov_unload:
	OSSL_PROVIDER_unload(prov);
free_ctx:
	OSSL_LIB_CTX_free(ctx);
exit:
	return ret;
}
