/* SPDX-License-Identifier: Apache-2.0 */
#ifndef REDSOCKS_TLS_SNI_H
#define REDSOCKS_TLS_SNI_H

#include <stddef.h>

#define TLS_SNI_HOSTNAME_MAX 253
#define TLS_SNI_PROBE_MAX (64 * 1024)

typedef enum tls_sni_result_t {
	TLS_SNI_NEED_MORE,
	TLS_SNI_FOUND,
	TLS_SNI_NO_SNI,
	TLS_SNI_INVALID
} tls_sni_result;

/* Inspect, never consume or modify, the original TLS records. The caller must
 * pass all bytes accumulated so far and provide HOSTNAME_MAX + 1 output bytes.
 * FOUND is returned only after validating the entire first ClientHello. */
tls_sni_result tls_sni_parse(const unsigned char *data, size_t length,
		char hostname[TLS_SNI_HOSTNAME_MAX + 1]);

#endif
