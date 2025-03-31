// SPDX-License-Identifier: GPL-2.0
/*
 * (C) Copyright 2018, Andre Przywara
 * (C) Copyright 2025, James Hilliard
 *
 * sunxi-toc0: dump very basic information about an Allwinner TOC0 image
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef WITH_OPENSSL
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#endif

#include "sunxi-fw.h"

#define TOC0_MAIN_INFO_NAME "TOC0.GLH"
#define BROM_STAMP_VALUE 0x5f0a6c39
#define TOC0_MAIN_MAGIC 0x89119800
#define TOC0_MAIN_END 0x3b45494d
#define TOC0_ITEM_END 0x3b454949

#define TOC0_ITEM_NAME_CERT 0x010101
#define TOC0_ITEM_NAME_FW 0x010202
#define TOC0_ITEM_NAME_KEY 0x010303

#define RSA_MOD_LEN 256
#define RSA_EXP_LEN 3

typedef struct {
	uint8_t name[8];
	uint32_t magic;
	uint32_t checksum;
	uint32_t serial;
	uint32_t status;
	uint32_t num_items;
	uint32_t length;
	uint8_t platform[4];
	uint8_t reserved[8];
	uint32_t end_marker;
} toc0_main_info;

typedef struct {
	uint32_t name;
	uint32_t offset;
	uint32_t length;
	uint32_t status;
	uint32_t type;
	uint32_t load_addr;
	uint8_t reserved[4];
	uint8_t end_marker[4];
} toc0_item_info;

struct toc0_key_item {
	uint32_t vendor_id;
	uint32_t key0_n_len;
	uint32_t key0_e_len;
	uint32_t key1_n_len;
	uint32_t key1_e_len;
	uint32_t sig_len;
	uint8_t key0[512];
	uint8_t key1[512];
	uint8_t reserved[32];
	uint8_t sig[256];
};

#define __packed __attribute__((__packed__))

struct __packed toc0_small_tag {
	uint8_t tag;
	uint8_t length;
};

typedef struct toc0_small_tag toc0_small_int;
typedef struct toc0_small_tag toc0_small_oct;
typedef struct toc0_small_tag toc0_small_seq;
typedef struct toc0_small_tag toc0_small_exp;

#define TOC0_LARGE_INT(len)                        \
	{                                          \
		0x02, 0x82, (len) >> 8, (len)&0xff \
	}
#define TOC0_LARGE_BIT(len)                        \
	{                                          \
		0x03, 0x82, (len) >> 8, (len)&0xff \
	}
#define TOC0_LARGE_SEQ(len)                        \
	{                                          \
		0x30, 0x82, (len) >> 8, (len)&0xff \
	}

struct __packed toc0_large_tag {
	uint8_t tag;
	uint8_t prefix;
	uint8_t length_hi;
	uint8_t length_lo;
};

typedef struct toc0_large_tag toc0_large_int;
typedef struct toc0_large_tag toc0_large_bit;
typedef struct toc0_large_tag toc0_large_seq;

struct __packed toc0_cert_item {
	toc0_large_seq tag_totalSequence;
	struct __packed toc0_totalSequence {
		toc0_large_seq tag_mainSequence;
		struct __packed toc0_mainSequence {
			toc0_small_exp tag_explicit0;
			struct __packed toc0_explicit0 {
				toc0_small_int tag_version;
				uint8_t version;
			} explicit0;
			toc0_small_int tag_serialNumber;
			uint8_t serialNumber;
			toc0_small_seq tag_signature;
			toc0_small_seq tag_issuer;
			toc0_small_seq tag_validity;
			toc0_small_seq tag_subject;
			toc0_large_seq tag_subjectPublicKeyInfo;
			struct __packed toc0_subjectPublicKeyInfo {
				toc0_small_seq tag_algorithm;
				toc0_large_seq tag_publicKey;
				struct __packed toc0_publicKey {
					toc0_large_int tag_n;
					uint8_t n[256];
					toc0_small_int tag_e;
					uint8_t e[3];
				} publicKey;
			} subjectPublicKeyInfo;
			toc0_small_exp tag_explicit3;
			struct __packed toc0_explicit3 {
				toc0_small_seq tag_extension;
				struct __packed toc0_extension {
					toc0_small_int tag_digest;
					uint8_t digest[32];
				} extension;
			} explicit3;
		} mainSequence;
		toc0_large_bit tag_sigSequence;
		struct __packed toc0_sigSequence {
			toc0_small_seq tag_algorithm;
			toc0_large_bit tag_signature;
			uint8_t signature[256];
		} sigSequence;
	} totalSequence;
};

static inline bool is_rsa_pubkey_tag(const uint8_t *buf)
{
	return (buf[0] == 0x02 && buf[1] == 0x82 && buf[2] == 0x01 &&
		buf[3] == 0x00 && buf[4 + RSA_MOD_LEN] == 0x02 &&
		buf[4 + RSA_MOD_LEN + 1] == 0x03 &&
		buf[4 + RSA_MOD_LEN + 2 + RSA_EXP_LEN] == 0xa3);
}

static const char *item_name(uint32_t id)
{
	switch (id) {
	case TOC0_ITEM_NAME_CERT:
		return "SBROMSW_CERTIF";
	case TOC0_ITEM_NAME_FW:
		return "SBROMSW_FW";
	case TOC0_ITEM_NAME_KEY:
		return "SBROMSW_KEY";
	default:
		return "UNKNOWN";
	}
}

static uint32_t calc_checksum(void *buff, uint32_t length)
{
	uint32_t *buf = buff;
	uint32_t sum = BROM_STAMP_VALUE;
	uint32_t i;

	for (i = 0; i < length / 4; i++)
		sum += buf[i];

	return sum;
}

#ifdef WITH_OPENSSL
static void dump_hex(const char *label, const uint8_t *data, size_t len,
		     FILE *stream)
{
	size_t i;

	fprintf(stream, "%s:", label);

	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			fprintf(stream, "\n  ");
		fprintf(stream, "%02x ", data[i]);
	}

	fprintf(stream, "\n");
}

static bool parse_cert_for_rotpk(const uint8_t *cert_buf, size_t cert_len,
				 FILE *stream)
{
	size_t i;
	uint8_t rotpk[512];
	uint8_t rotpk_hash[SHA256_DIGEST_LENGTH];
	const uint8_t *mod;
	const uint8_t *exp;

	for (i = 0; i + 4 + RSA_MOD_LEN + 2 + RSA_EXP_LEN <= (ssize_t)cert_len;
	     i++) {
		if (is_rsa_pubkey_tag(&cert_buf[i])) {
			mod = &cert_buf[i + 4];
			exp = &cert_buf[i + 4 + RSA_MOD_LEN + 2];

			memset(rotpk, 0x91, sizeof(rotpk));
			memcpy(rotpk, mod, RSA_MOD_LEN);
			memcpy(rotpk + RSA_MOD_LEN, exp, RSA_EXP_LEN);

			dump_hex("  ROTPK (modulus + exponent)", rotpk,
				 RSA_MOD_LEN + RSA_EXP_LEN, stream);
			SHA256(rotpk, sizeof(rotpk), rotpk_hash);
			dump_hex("  ROTPK SHA256 (from CERTIF)", rotpk_hash,
				 sizeof(rotpk_hash), stream);
			return true;
		}
	}

	fprintf(stderr,
		"ROTPK extraction failed: RSA key structure not found in certificate\n");
	return false;
}

static int verify_signature(const uint8_t *sig, size_t sig_len,
			    const uint8_t *tbs, size_t tbs_len,
			    const uint8_t *mod, size_t mod_len,
			    const uint8_t *exp, size_t exp_len, FILE *stream)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	int ret = -1;

	bld = OSSL_PARAM_BLD_new();
	if (!bld ||
	    !OSSL_PARAM_BLD_push_BN(bld, "n", BN_bin2bn(mod, mod_len, NULL)) ||
	    !OSSL_PARAM_BLD_push_BN(bld, "e", BN_bin2bn(exp, exp_len, NULL))) {
		fprintf(stderr, "Failed to build RSA parameters\n");
		goto cleanup;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		fprintf(stderr, "OSSL_PARAM_BLD_to_param failed\n");
		goto cleanup;
	}

	pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pkctx || EVP_PKEY_fromdata_init(pkctx) <= 0 ||
	    EVP_PKEY_fromdata(pkctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
		fprintf(stderr, "EVP_PKEY_fromdata failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "EVP_MD_CTX_new failed\n");
		goto cleanup;
	}

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
		fprintf(stderr, "EVP_DigestVerifyInit failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (EVP_DigestVerifyUpdate(ctx, tbs, tbs_len) <= 0) {
		fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	if (EVP_DigestVerifyFinal(ctx, sig, sig_len) != 1) {
		fprintf(stderr, "EVP_DigestVerifyFinal failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	fprintf(stream, "  Signature verification: SUCCESS\n");
	ret = 0;

cleanup:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (pkctx)
		EVP_PKEY_CTX_free(pkctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);

	return ret;
}

int parse_cert_item(const uint8_t *buf, size_t len,
		    const uint8_t *expected_digest)
{
	const struct toc0_cert_item *cert_item = (const void *)buf;
	uint8_t cert_digest[SHA256_DIGEST_LENGTH];

	const struct toc0_totalSequence *totalSequence =
		&cert_item->totalSequence;
	const struct toc0_sigSequence *sigSequence =
		&totalSequence->sigSequence;
	const struct toc0_publicKey *publicKey =
		&totalSequence->mainSequence.subjectPublicKeyInfo.publicKey;

	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *pub_params = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int ret = -1;

	SHA256((uint8_t *)totalSequence, sizeof(struct toc0_mainSequence),
	       cert_digest);

	bld = OSSL_PARAM_BLD_new();
	n = BN_bin2bn(publicKey->n, sizeof(publicKey->n), NULL);
	e = BN_bin2bn(publicKey->e, sizeof(publicKey->e), NULL);

	if (!n || !e) {
		fprintf(stderr, "Failed to create BIGNUMs for RSA key\n");
		goto cleanup;
	}

	if (!bld || !OSSL_PARAM_BLD_push_BN(bld, "n", n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, "e", e)) {
		fprintf(stderr, "Failed to build RSA params\n");
		goto cleanup;
	}

	pub_params = OSSL_PARAM_BLD_to_param(bld);
	if (!pub_params) {
		fprintf(stderr, "OSSL_PARAM_BLD_to_param failed\n");
		goto cleanup;
	}

	pkctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!pkctx || EVP_PKEY_fromdata_init(pkctx) <= 0 ||
	    EVP_PKEY_fromdata(pkctx, &pkey, EVP_PKEY_PUBLIC_KEY, pub_params) <=
		    0) {
		fprintf(stderr, "EVP_PKEY_fromdata failed\n");
		ERR_print_errors_fp(stderr);
		goto cleanup;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
		goto cleanup;
	}

	if (EVP_PKEY_verify_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
	    EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		fprintf(stderr, "Failed to set up verification context\n");
		goto cleanup;
	}

	if (EVP_PKEY_verify(ctx, sigSequence->signature,
			    sizeof(sigSequence->signature), cert_digest,
			    SHA256_DIGEST_LENGTH) <= 0) {
		fprintf(stderr, "Bad certificate signature\n");
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (pkctx)
		EVP_PKEY_CTX_free(pkctx);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (pub_params)
		OSSL_PARAM_free(pub_params);
	if (n)
		BN_free(n);
	if (e)
		BN_free(e);

	return ret;
}

static void parse_key_item(const uint8_t *buf, size_t len, FILE *stream)
{
	const struct toc0_key_item *item;
	size_t signed_len;

	if (len < sizeof(struct toc0_key_item)) {
		fprintf(stderr, "Error: Buffer too small (len=%zu)\n", len);
		return;
	}

	item = (const struct toc0_key_item *)buf;
	signed_len = (size_t)(item->sig - buf);

	verify_signature(item->sig, item->sig_len, buf, signed_len, item->key0,
			 item->key0_n_len, item->key0 + item->key0_n_len,
			 item->key0_e_len, stream);
}

#endif

static void print_toc0_item(const toc0_item_info *item,
			    const uint8_t *toc0_data, size_t data_size,
			    const uint8_t *fw_data, size_t fw_size,
			    FILE *stream)
{
#ifdef WITH_OPENSSL
	const uint8_t *blob;
#endif

	if (memcmp(item->end_marker, "IIE;", 4) != 0) {
		fprintf(stderr, "Invalid TOC0 item end marker\n");
		exit(EXIT_FAILURE);
	}

	if (item->offset + item->length > data_size) {
		fprintf(stderr, "Item offset and length exceed data size\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stream, "\nItem:\n");
	fprintf(stream, "  Name: 0x%06x (%s)\n", item->name,
		item_name(item->name));
	fprintf(stream, "  Offset: 0x%08x\n", item->offset);
	fprintf(stream, "  Length: %u bytes\n", item->length);
	fprintf(stream, "  Status: 0x%08x\n", item->status);
	fprintf(stream, "  Type: %u\n", item->type);
	fprintf(stream, "  Run Address: 0x%08x\n", item->load_addr);

#ifdef WITH_OPENSSL
	blob = toc0_data + item->offset;
#endif

	switch (item->name) {
	case TOC0_ITEM_NAME_CERT:
		fprintf(stream, "  -> Certificate File\n");
#ifdef WITH_OPENSSL
		parse_cert_for_rotpk(blob, item->length, stream);
		parse_cert_item(blob, item->length, fw_data);
#else
		fprintf(stderr, "Skipping cert parsing (OpenSSL disabled)\n");
#endif
		break;
	case TOC0_ITEM_NAME_FW:
		fprintf(stream, "  -> Signed Boot Firmware\n");
		break;
	case TOC0_ITEM_NAME_KEY:
		fprintf(stream, "  -> Key Ladder or Key Item\n");
#ifdef WITH_OPENSSL
		parse_key_item(blob, item->length, stream);
#else
		fprintf(stderr,
			"Skipping key item parsing (OpenSSL disabled)\n");
#endif
		break;
	default:
		fprintf(stderr, "Unknown item type 0x%08x\n", item->name);
		exit(EXIT_FAILURE);
	}
}

void output_toc0_info(void *sector, FILE *inf, FILE *stream, bool verbose)
{
	toc0_main_info main_header;
	size_t bytes_in_sector = 512;
	size_t remain;
	uint32_t data_size;
	uint8_t *toc0_data;
	toc0_main_info *main_info;
	const toc0_item_info *items;
	const uint8_t *fw_data = NULL;
	size_t fw_size = 0;

	memcpy(&main_header, sector, sizeof(main_header));

	if (memcmp(main_header.name, TOC0_MAIN_INFO_NAME,
		   sizeof(main_header.name)) != 0) {
		fprintf(stderr, "Invalid TOC0 name: '%.8s' (expected '%s')\n",
			main_header.name, TOC0_MAIN_INFO_NAME);
		return;
	}

	if (main_header.magic != TOC0_MAIN_MAGIC) {
		fprintf(stderr,
			"Invalid TOC0 magic: 0x%08x (expected 0x%08x)\n",
			main_header.magic, TOC0_MAIN_MAGIC);
		return;
	}

	if (main_header.end_marker != TOC0_MAIN_END) {
		fprintf(stderr,
			"Invalid TOC0 end marker: 0x%08x (expected 0x%08x)\n",
			main_header.end_marker, TOC0_MAIN_END);
		return;
	}

	data_size = main_header.length;

	if (data_size < sizeof(toc0_main_info)) {
		fprintf(stderr, "Invalid/too-small TOC0 length from header\n");
		return;
	}

	toc0_data = malloc(data_size);

	if (!toc0_data) {
		fprintf(stderr, "Failed to allocate %u bytes for TOC0 data\n",
			data_size);
		return;
	}

	if (bytes_in_sector > data_size)
		bytes_in_sector = data_size;

	memcpy(toc0_data, sector, bytes_in_sector);

	remain = data_size - bytes_in_sector;

	if (remain > 0) {
		if (fread(toc0_data + bytes_in_sector, 1, remain, inf) !=
		    (size_t)remain) {
			fprintf(stderr,
				"Failed to read the remaining %zu bytes of TOC0\n",
				(size_t)remain);
			free(toc0_data);
			return;
		}
	}

	main_info = (toc0_main_info *)toc0_data;

	fprintf(stream, "TOC0 Name: '%.8s'\n", main_info->name);
	fprintf(stream, "Serial Number: 0x%08x\n", main_info->serial);
	fprintf(stream, "Status: 0x%08x\n", main_info->status);
	fprintf(stream, "Number of TOC0 items: %d\n", main_info->num_items);
	fprintf(stream, "Total size: %d bytes\n", main_info->length);

	if (verbose) {
		fprintf(stream, "Platform: %02x %02x %02x %02x\n",
			main_info->platform[0], main_info->platform[1],
			main_info->platform[2], main_info->platform[3]);
	}

	if (main_info->length <= data_size) {
		uint32_t calc = calc_checksum(toc0_data, main_info->length);
		uint32_t stored = main_info->checksum;

		if (calc != 2 * stored) {
			fprintf(stderr, "Checksum validation failed\n");
			fprintf(stream, "Checksum: 0x%08x (INVALID)\n", stored);
			fprintf(stream, "Calculated Checksum: 0x%08x\n", calc);
			free(toc0_data);
			return;
		}
	} else {
		fprintf(stderr, "TOC0 length field exceeds buffer size\n");
		free(toc0_data);
		return;
	}

	if (sizeof(toc0_main_info) +
		    main_info->num_items * sizeof(toc0_item_info) >
	    data_size) {
		fprintf(stderr, "Not enough data for all TOC0 items\n");
		free(toc0_data);
		return;
	}

	items = (toc0_item_info *)(toc0_data + sizeof(toc0_main_info));

	for (uint32_t i = 0; i < main_info->num_items; i++) {
		if (items[i].name == TOC0_ITEM_NAME_FW) {
			if (items[i].offset + items[i].length <= data_size) {
				fw_data = toc0_data + items[i].offset;
				fw_size = items[i].length;
			}
			break;
		}
	}

	for (uint32_t i = 0; i < main_info->num_items; i++) {
		if ((uintptr_t)(&items[i]) + sizeof(toc0_item_info) -
			    (uintptr_t)toc0_data >
		    data_size) {
			fprintf(stderr, "Truncated item info\n");
			break;
		}
		print_toc0_item(&items[i], toc0_data, data_size, fw_data,
				fw_size, stream);
	}

	free(toc0_data);
}
