#include <stdio.h>
#include <string.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include "algo/blake3.h"

#define BLAKE3_DEFAULT_LEN (32)
#define BLAKE3_MAX_BYTES (64)

OSSL_provider_init_fn ossl_null_provider_init;
typedef void (*funcptr_t)(void);

struct blake3_ctx {
	void *prov;
	size_t out_len;
	blake3_hasher md;
};

static void *blake3_newctx(void *vctx)
{
	struct blake3_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));

	if (ctx != NULL) {
		ctx->prov = vctx;
		ctx->out_len = BLAKE3_DEFAULT_LEN;
	}

	return ctx;
}

static void *blake3_dupctx(void *vctx)
{
	struct blake3_ctx *src = vctx;
	struct blake3_ctx *dst = NULL;

	dst = blake3_newctx(NULL);

	if (dst == NULL) {
		return NULL;
	}

	dst->prov = src->prov;
	dst->out_len = src->out_len;

	return dst;
}

static void blake3_freectx(void *vctx)
{
	struct blake3_ctx *ctx = vctx;

	OPENSSL_free(ctx);
}

int blake3_digest_init(void *vctx)
{
	struct blake3_ctx *ctx = vctx;

	blake3_hasher_init(&ctx->md);

	return 1;
}

int blake3_digest_update(void *vctx, const unsigned char *in, size_t inl)
{
	struct blake3_ctx *ctx = vctx;

	blake3_hasher_update(&ctx->md, in, inl);
	return 1;
}

int blake3_digest_final(void *vctx, unsigned char *out, size_t *outl,
			size_t outsz)
{
	struct blake3_ctx *ctx = vctx;
	fprintf(stderr, "bytes %lu\n", outsz);

	*outl = outsz;
	if (outsz != 0)
		blake3_hasher_finalize(&ctx->md, out, outsz);

	return 1;
}

// clang-format off
static const OSSL_PARAM blake3_mutable_params[] = {
		OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
		OSSL_PARAM_END
};
// clang-format on

static const OSSL_PARAM *blake3_gettable_params(void)
{
	return blake3_mutable_params;
}

static int blake3_get_params(void *vctx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL) {
		return OSSL_PARAM_set_size_t(p, BLAKE3_DEFAULT_LEN);
	}

	return 1;
}

static const OSSL_PARAM *blake3_gettable_ctx_params(void)
{
	fprintf(stderr, "%s\n", __func__);
	return blake3_mutable_params;
}

static const OSSL_PARAM *blake3_settable_ctx_params(void)
{
	fprintf(stderr, "%s\n", __func__);
	return blake3_mutable_params;
}

static int blake3_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	struct blake3_ctx *ctx = vctx;
	OSSL_PARAM *p;

	fprintf(stderr, "%s\n", __func__);

	if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL) {
		return OSSL_PARAM_set_size_t(p, ctx->out_len);
	}

	return 1;
}

static int blake3_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	struct blake3_ctx *ctx = vctx;
	const OSSL_PARAM *p;

	fprintf(stderr, "%s\n", __func__);

	if ((p = OSSL_PARAM_locate_const(params, OSSL_DIGEST_PARAM_SIZE)) !=
	    NULL) {
		size_t size;

		if (!OSSL_PARAM_get_size_t(p, &size) || size < 1 ||
		    size > BLAKE3_MAX_BYTES) {
			fprintf(stderr, "PROV_R_NOT_XOF_OR_INVALID_LENGTH\n");
			return 0;
		}

		ctx->out_len = size;
	}

	return 1;
}

// clang-format off
static const OSSL_DISPATCH blake3_functions[] = {
	{ OSSL_FUNC_DIGEST_NEWCTX, (funcptr_t)blake3_newctx },
	{ OSSL_FUNC_DIGEST_DUPCTX, (funcptr_t)blake3_dupctx },
	{ OSSL_FUNC_DIGEST_FREECTX, (funcptr_t)blake3_freectx },
	{ OSSL_FUNC_DIGEST_INIT, (funcptr_t)blake3_digest_init },
	{ OSSL_FUNC_DIGEST_UPDATE, (funcptr_t)blake3_digest_update },
	{ OSSL_FUNC_DIGEST_FINAL, (funcptr_t)blake3_digest_final },
	{ OSSL_FUNC_DIGEST_GET_PARAMS, (funcptr_t)blake3_get_params },
	{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (funcptr_t)blake3_gettable_params },
	{ OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (funcptr_t)blake3_get_ctx_params },
	{ OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (funcptr_t)blake3_set_ctx_params },
	{ OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (funcptr_t)blake3_gettable_ctx_params },
	{ OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (funcptr_t)blake3_settable_ctx_params },
	/* OpenSSL doesn't support DIGEST_SET_PARAMS, but BLAKE3 can adjust the
	 * output length when finalize is called. This should be implemented
	 * with *_SET_PARAMS. Instead, we have to overload the CTX_PARAMS APIs,
	 * which aren't called automatically.
	 *
	 * { OSSL_FUNC_DIGEST_SET_PARAMS, (funcptr_t)blake3_set_params },
	 * { OSSL_FUNC_DIGEST_SETTABLE_PARAMS, (funcptr_t)blake3_settable_params },
	 */
	{ 0, NULL }
};

static const OSSL_ALGORITHM blake3_digests[] = {
	{ "blake3", NULL, blake3_functions },
	{ NULL, NULL, NULL } };
// clang-format on

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *blake3_operation(void *vprovctx, int operation_id,
					      int *no_cache)
{
	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return blake3_digests;
	}
	return NULL;
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)blake3_operation },
	{ 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out, void **provctx)
{
	*out = provider_functions;
	*provctx = (void *)handle;

	return 1;
}
