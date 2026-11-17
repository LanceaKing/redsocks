/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <string.h>
#include "tls-sni.h"

typedef struct tls_reader_t {
	const unsigned char *data;
	size_t length, position, record_left, hello_left;
} tls_reader;

/* A reader across TLS plaintext records, including split handshake headers.
 * No allocation, recursion, or copies proportional to the ClientHello size. */
static tls_sni_result read_bytes(tls_reader *r, unsigned char *out, size_t n)
{
	while (n) {
		if (!r->record_left) {
			size_t avail = r->length - r->position;
			const unsigned char *p = r->data + r->position;
			if (avail && p[0] != 22)
				return TLS_SNI_INVALID;
			if (avail < 5)
				return TLS_SNI_NEED_MORE;
			if (p[1] != 3 || p[2] > 3)
				return TLS_SNI_INVALID;
			r->record_left = ((size_t)p[3] << 8) | p[4];
			if (!r->record_left || r->record_left > 16384)
				return TLS_SNI_INVALID;
			r->position += 5;
		}
		size_t count = r->length - r->position;
		if (!count)
			return TLS_SNI_NEED_MORE;
		if (count > r->record_left)
			count = r->record_left;
		if (count > n)
			count = n;
		if (out) {
			memcpy(out, r->data + r->position, count);
			out += count;
		}
		r->position += count;
		r->record_left -= count;
		n -= count;
	}
	return TLS_SNI_FOUND; /* internal success, not yet a validated SNI */
}

static tls_sni_result take(tls_reader *r, unsigned char *out, size_t n)
{
	if (n > r->hello_left)
		return TLS_SNI_INVALID;
	tls_sni_result result = read_bytes(r, out, n);
	if (result == TLS_SNI_FOUND)
		r->hello_left -= n;
	return result;
}

static int valid_hostname(const char *name, size_t n)
{
	size_t label = 0;
	int numeric = 1;
	if (!n || n > TLS_SNI_HOSTNAME_MAX)
		return 0;
	for (size_t i = 0; i < n; ++i) {
		unsigned char c = (unsigned char)name[i];
		if (c == '.') {
			if (!label || name[i - 1] == '-')
				return 0;
			label = 0;
		} else {
			int digit = c >= '0' && c <= '9';
			int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
			if ((!digit && !alpha && c != '-') || (!label && c == '-') || ++label > 63)
				return 0;
			if (!digit)
				numeric = 0;
		}
	}
	/* Numeric-only names include IPv4 literals. Colons, brackets, NUL and
	 * request delimiters have already been rejected by the DNS alphabet. */
	return label && name[n - 1] != '-' && !numeric;
}

#define TAKE(out, n) do { \
	tls_sni_result result_ = take(&r, (out), (n)); \
	if (result_ != TLS_SNI_FOUND) return result_; \
} while (0)
#define U16(p) (((size_t)(p)[0] << 8) | (p)[1])

tls_sni_result tls_sni_parse(const unsigned char *data, size_t length,
		char hostname[TLS_SNI_HOSTNAME_MAX + 1])
{
	tls_reader r = { data, length, 0, 0, 0 };
	unsigned char field[4];
	int found = 0, seen_sni = 0;
	hostname[0] = '\0';
	if (!length)
		return TLS_SNI_NEED_MORE;
	if (length > TLS_SNI_PROBE_MAX)
		return TLS_SNI_INVALID;
	if (data[0] != 22)
		return TLS_SNI_NO_SNI;
	tls_sni_result result = read_bytes(&r, field, 4);
	if (result != TLS_SNI_FOUND)
		return result;
	if (field[0] != 1)
		return TLS_SNI_INVALID;
	r.hello_left = ((size_t)field[1] << 16) | ((size_t)field[2] << 8) | field[3];
	if (r.hello_left > TLS_SNI_PROBE_MAX - 4)
		return TLS_SNI_INVALID;
	TAKE(field, 2); /* ClientHello.legacy_version */
	if (field[0] != 3 || field[1] > 3)
		return TLS_SNI_INVALID;
	TAKE(NULL, 32); /* random */
	TAKE(field, 1);
	if (field[0] > 32)
		return TLS_SNI_INVALID;
	TAKE(NULL, field[0]); /* legacy_session_id */
	TAKE(field, 2);
	size_t n = U16(field);
	if (!n || n % 2)
		return TLS_SNI_INVALID;
	TAKE(NULL, n); /* cipher_suites */
	TAKE(field, 1);
	if (!field[0])
		return TLS_SNI_INVALID;
	TAKE(NULL, field[0]); /* legacy_compression_methods */
	if (!r.hello_left)
		return TLS_SNI_NO_SNI;
	TAKE(field, 2);
	if (U16(field) != r.hello_left)
		return TLS_SNI_INVALID;
	while (r.hello_left) {
		TAKE(field, 4);
		size_t type = U16(field), ext_left = U16(field + 2);
		if (ext_left > r.hello_left)
			return TLS_SNI_INVALID;
		if (type != 0) {
			TAKE(NULL, ext_left); /* Includes GREASE and unknown extensions. */
			continue;
		}
		if (seen_sni++ || ext_left < 2)
			return TLS_SNI_INVALID;
		TAKE(field, 2);
		ext_left -= 2;
		if (!ext_left || U16(field) != ext_left)
			return TLS_SNI_INVALID;
		while (ext_left) {
			if (ext_left < 3)
				return TLS_SNI_INVALID;
			TAKE(field, 3);
			ext_left -= 3;
			n = U16(field + 1);
			if (!n || n > ext_left)
				return TLS_SNI_INVALID;
			if (field[0] == 0) {
				if (found || n > TLS_SNI_HOSTNAME_MAX)
					return TLS_SNI_INVALID;
				TAKE((unsigned char *)hostname, n);
				if (!valid_hostname(hostname, n))
					return TLS_SNI_INVALID;
				hostname[n] = '\0';
				found = 1;
			} else {
				TAKE(NULL, n);
			}
			ext_left -= n;
		}
	}
	return found ? TLS_SNI_FOUND : TLS_SNI_NO_SNI;
}
