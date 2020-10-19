#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "test_vectors.h"

#define BLAKE3_DIGEST_LENGTH (32)

#define max(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a > _b ? _a : _b;                                             \
	})

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

struct test_ctx {
	EVP_MD_CTX *ctx;
	OSSL_PROVIDER *prov;
	EVP_MD *md;
};

#define EXEC_TEST(number, c, p, m)                                             \
	run_test((struct test_ctx){ .ctx = c, .prov = p, .md = m },            \
		 RETRIEVE_TEST_VECTOR(number), "TEST_CASE_" #number)

// Caller is expected to allocate an appropriately sized buffer
int generate_input(uint8_t *buf, size_t len)
{
	for (int i = 0; i < len; i++) {
		buf[i] = i % TEST_INPUT_MODULO;
	}
}

int run_test(struct test_ctx context, struct test_vector vec, char *test_name)
{
	uint8_t *out_buf;
	uint8_t *in_buf;
	int ret = 0;

	out_buf = (uint8_t *)calloc(TEST_HASH_LEN, 1);
	if (vec.input_len) {
		in_buf = (uint8_t *)calloc(
			max(vec.input_len, BLAKE3_DIGEST_LENGTH), 1);
		generate_input(in_buf, vec.input_len);
	}

	TEST_TRUE(EVP_DigestInit_ex(context.ctx, context.md, NULL));
	TEST_TRUE(EVP_DigestUpdate(context.ctx, in_buf, vec.input_len));
	TEST_TRUE(EVP_DigestFinal_ex(context.ctx, out_buf, NULL));

	for (int i = 0; i < BLAKE3_DIGEST_LENGTH; i++) {
		if (out_buf[i] != vec.hash[i]) {
			fprintf(stderr, "%s Failed\n", test_name);
			ret = 1;
			break;
		}
	}

	if (!ret)
		printf("%s passed!\n", test_name);

	free(out_buf);

	if (vec.input_len)
		free(in_buf);
	return ret;
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

	/* Tests 0-4 */
	ret = EXEC_TEST(01, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(02, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(03, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(04, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 5-9 */
	ret = EXEC_TEST(05, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(06, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(07, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(08, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(09, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 10-14 */
	ret = EXEC_TEST(10, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(11, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(12, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(13, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(14, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 15-19 */
	ret = EXEC_TEST(15, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(16, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(17, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(18, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(19, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 20-24 */
	ret = EXEC_TEST(20, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(21, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(22, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(23, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(24, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 25-29 */
	ret = EXEC_TEST(25, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(26, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(27, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(28, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(29, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Tests 30-34 */
	ret = EXEC_TEST(30, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(31, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(32, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(33, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	ret = EXEC_TEST(34, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

	/* Test 35 */
	ret = EXEC_TEST(35, md_ctx, prov, md);
	if (ret)
		goto free_md_ctx;

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