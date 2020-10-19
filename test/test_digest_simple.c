#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#define BLAKE3_DIGEST_LENGTH (32)

#define NON_NULL(expr, fail_expr)                                              \
	if ((expr) == NULL) {                                                  \
		ERR_print_errors_fp(stderr);                                   \
		fail_expr;                                                     \
	}

#define TEST_TRUE(expr)                                                        \
	if ((expr) != 1) {                                                     \
		ERR_print_errors_fp(stderr);                                   \
		fprintf(stderr, "Failed %s:%i %s %i\n", __FILE__, __LINE__,    \
			#expr, (expr));                                        \
		return 1;                                                      \
	}

int run_test(EVP_MD_CTX *ctx, OSSL_PROVIDER *prov, EVP_MD *md)
{
	uint8_t *out;
	int tmp = 0;
	const char msg[] = "Hello, World!";
	const uint8_t expected[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				     0x00, 0x00, 0x00, 0x00 };

	out = (uint8_t *)calloc(BLAKE3_DIGEST_LENGTH, 1);
	TEST_TRUE(EVP_DigestInit_ex(ctx, md, NULL));
	TEST_TRUE(EVP_DigestUpdate(ctx, msg, sizeof(msg)));
	TEST_TRUE(EVP_DigestFinal_ex(ctx, out, &tmp));

	for (int i = 0; i < sizeof(expected); i++) {
		printf("0x%x ", out[i]);
	}
	puts("\n");

	free(out);
	return 0;
}

int main()
{
	OPENSSL_CTX *ctx;
	OSSL_PROVIDER *prov = NULL;
	EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx;
	int ret = 0;

	NON_NULL((ctx = OPENSSL_CTX_new()), ret = 1; goto exit);
	NON_NULL((prov = OSSL_PROVIDER_load(ctx, "blake3")), ret = 1;
		 goto free_ctx);
	NON_NULL((md = EVP_MD_fetch(ctx, "blake3", NULL)), ret = 1;
		 goto prov_unload);
	NON_NULL((md_ctx = EVP_MD_CTX_new()), ret = 1; goto free_md);

	ret = run_test(md_ctx, prov, md);
free_md_ctx:
	EVP_MD_CTX_free(md_ctx);
free_md:
	EVP_MD_free(md);
prov_unload:
	OSSL_PROVIDER_unload(prov);
free_ctx:
	OPENSSL_CTX_free(ctx);
exit:
	return ret;
}