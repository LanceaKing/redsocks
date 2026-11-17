/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "tls-sni.h"

typedef struct bytes_t { unsigned char b[70000]; size_t n; } bytes;
static unsigned int checks;
#define CHECK(x) do { assert(x); ++checks; } while (0)
static void put(bytes *b, unsigned int v) { assert(b->n < sizeof(b->b)); b->b[b->n++] = v; }
static void u16(bytes *b, size_t v) { put(b, v >> 8); put(b, v); }
static void add(bytes *b, const void *data, size_t n) { assert(n <= sizeof(b->b) - b->n); memcpy(b->b + b->n, data, n); b->n += n; }
static void extension(bytes *b, unsigned int type, const void *data, size_t n) { u16(b, type); u16(b, n); add(b, data, n); }

static bytes hello(const char *name, size_t name_len, size_t padding, int tls13)
{
	bytes body = {{0}, 0}, ext = {{0}, 0}, hs = {{0}, 0};
	u16(&body, 0x0303);
	for (int i = 0; i < 32; ++i) put(&body, i);
	put(&body, 0); u16(&body, 2); u16(&body, tls13 ? 0x1301 : 0xc02f);
	put(&body, 1); put(&body, 0);
	extension(&ext, 0xaaaa, "GREASE", 6);
	if (padding) {
		u16(&ext, 21); u16(&ext, padding);
		for (size_t i = 0; i < padding; ++i) put(&ext, 0);
	}
	if (name) {
		bytes sni = {{0}, 0};
		u16(&sni, name_len + 3); put(&sni, 0); u16(&sni, name_len); add(&sni, name, name_len);
		extension(&ext, 0, sni.b, sni.n);
	}
	if (tls13) {
		const unsigned char versions[] = {2, 3, 4};
		extension(&ext, 43, versions, sizeof(versions));
	}
	extension(&ext, 0x1234, "unknown", 7);
	u16(&body, ext.n); add(&body, ext.b, ext.n);
	put(&hs, 1); put(&hs, body.n >> 16); u16(&hs, body.n); add(&hs, body.b, body.n);
	return hs;
}

static bytes records(const bytes *hs, size_t fragment)
{
	bytes wire = {{0}, 0};
	for (size_t pos = 0; pos < hs->n;) {
		size_t n = hs->n - pos;
		if (n > fragment) n = fragment;
		put(&wire, 22); u16(&wire, 0x0301); u16(&wire, n);
		add(&wire, hs->b + pos, n); pos += n;
	}
	return wire;
}

static void valid(const char *name, size_t fragment, size_t padding, int tls13)
{
	bytes hs = hello(name, strlen(name), padding, tls13), wire = records(&hs, fragment), original = wire;
	char out[TLS_SNI_HOSTNAME_MAX + 1];
	for (size_t i = 0; i < wire.n; ++i)
		CHECK(tls_sni_parse(wire.b, i, out) == TLS_SNI_NEED_MORE);
	CHECK(tls_sni_parse(wire.b, wire.n, out) == TLS_SNI_FOUND);
	CHECK(strcmp(out, name) == 0);
	CHECK(memcmp(wire.b, original.b, wire.n) == 0);
}

int main(void)
{
	char out[TLS_SNI_HOSTNAME_MAX + 1], long_name[254];
	const size_t fragments[] = {1, 2, 3, 4, 7, 41, 16384};
	for (size_t i = 0; i < sizeof(fragments) / sizeof(fragments[0]); ++i) {
		valid("www.temu.com", fragments[i], 0, 0);
		valid("www.temu.com", fragments[i], 0, 1);
	}
	memset(long_name, 'a', 253);
	long_name[63] = long_name[127] = long_name[191] = '.';
	long_name[253] = 0;
	valid(long_name, 5, 0, 1);
	valid("records.example.com", 16384, 17000, 1);
	CHECK(tls_sni_parse((const unsigned char *)"GET / HTTP/1.1", 14, out) == TLS_SNI_NO_SNI);
	bytes hs = hello(NULL, 0, 0, 0), wire = records(&hs, 9);
	CHECK(tls_sni_parse(wire.b, wire.n, out) == TLS_SNI_NO_SNI);
	const char *bad[] = {"", "127.0.0.1", "123", "::1", "[::1]", "bad\r\nX:1", "a/b", "a b", "a\tb", ".a", "a.", "a..b", "-bad.com", "bad-.com", "bad_foo.com", "bad\xff.com"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
		hs = hello(bad[i], strlen(bad[i]), 0, 1); wire = records(&hs, 13);
		CHECK(tls_sni_parse(wire.b, wire.n, out) == TLS_SNI_INVALID);
	}
	hs = hello("foo\0bar.com", 11, 0, 1); wire = records(&hs, 2);
	CHECK(tls_sni_parse(wire.b, wire.n, out) == TLS_SNI_INVALID);
	memset(long_name, 'a', 64); memcpy(long_name + 64, ".com", 5);
	hs = hello(long_name, strlen(long_name), 0, 0); wire = records(&hs, 16384);
	CHECK(tls_sni_parse(wire.b, wire.n, out) == TLS_SNI_INVALID);
	hs = hello("www.temu.com", 12, 0, 1); wire = records(&hs, 16384);
	/* Invalid record, handshake, cipher-list, and extension vector lengths. */
	const size_t positions[] = {1, 2, 3, 5, 6, 7, 8, 44, 45, 50};
	for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); ++i) {
		bytes corrupt = wire; corrupt.b[positions[i]] = 0xff;
		CHECK(tls_sni_parse(corrupt.b, corrupt.n, out) == TLS_SNI_INVALID);
	}
	/* Validate all later extensions even after a valid SNI has been found. */
	bytes corrupt = wire; corrupt.b[corrupt.n - 9] = 0xff;
	CHECK(tls_sni_parse(corrupt.b, corrupt.n, out) == TLS_SNI_INVALID);
	hs = hello("limit.example", 13, 65430, 0); wire = records(&hs, 16384);
	CHECK(wire.n > TLS_SNI_PROBE_MAX);
	CHECK(tls_sni_parse(wire.b, TLS_SNI_PROBE_MAX, out) == TLS_SNI_NEED_MORE);
	CHECK(tls_sni_parse(wire.b, TLS_SNI_PROBE_MAX + 1, out) == TLS_SNI_INVALID);
	/* Deterministic malformed-input coverage under ASan/UBSan. */
	uint32_t random = 42;
	for (unsigned int i = 0; i < 20000; ++i) {
		unsigned char fuzz[1024];
		random = random * 1664525u + 1013904223u;
		size_t n = random % sizeof(fuzz);
		for (size_t j = 0; j < n; ++j) {
			random = random * 1664525u + 1013904223u; fuzz[j] = random >> 24;
		}
		if (i % 2 && n >= 5) { fuzz[0] = 22; fuzz[1] = 3; fuzz[2] = 1; }
		tls_sni_parse(fuzz, n, out);
	}
	printf("TLS SNI parser: %u checks and 20000 malformed inputs passed\n", checks);
	return 0;
}
