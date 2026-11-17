/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 *
 * http-connect upstream module for redsocks
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "redsocks.h"
#include "http-auth.h"
#include "tls-sni.h"
#include "utils.h"

typedef enum httpc_state_t {
	httpc_new,
	httpc_request_sent,
	httpc_reply_came, // 200 OK came, skipping headers...
	httpc_headers_skipped, // starting pump!
	httpc_no_way, // proxy can't handle the request
	httpc_MAX,
} httpc_state;


#define HTTP_HEAD_WM_HIGH (64 * 1024)

typedef struct httpc_client_t {
	struct event probe_timer;
	everrorcb original_errorcb;
	char authority[TLS_SNI_HOSTNAME_MAX + 7]; /* hostname, colon, port, NUL */
	unsigned int auth_retries;
	bool timer_active;
	bool target_decided;
} httpc_client;

static void httpc_client_fini(redsocks_client *client)
{
	httpc_client *data = red_payload(client);
	if (data->timer_active) {
		evtimer_del(&data->probe_timer);
		data->timer_active = false;
	}
	if (client->client && data->original_errorcb)
		client->client->errorcb = data->original_errorcb;
}

static void httpc_choose_target(redsocks_client *client, const char *hostname, const char *reason)
{
	httpc_client *data = red_payload(client);
	char ip[INET_ADDRSTRLEN];
	if (data->target_decided)
		return;
	data->target_decided = true;
	httpc_client_fini(client);
	if (!hostname) {
		hostname = inet_ntop(AF_INET, &client->destaddr.sin_addr, ip, sizeof(ip));
		if (!hostname) {
			redsocks_drop_client(client);
			return;
		}
	}
	snprintf(data->authority, sizeof(data->authority), "%s:%u", hostname,
		ntohs(client->destaddr.sin_port));
	redsocks_log_error(client, reason ? LOG_NOTICE : LOG_INFO, "HTTP CONNECT target=%s source=%s reason=%s",
		data->authority, reason ? "original_ip" : "sni", reason ? reason : "found");
	/* Keep every sniffed byte in input, and apply backpressure while CONNECT
	 * and possible 407 reconnections are in progress. */
	client->client->readcb = NULL;
	if (bufferevent_disable(client->client, EV_READ) != 0) {
		redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
		redsocks_drop_client(client);
		return;
	}
	redsocks_connect_relay(client);
}

static void httpc_probe_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	char hostname[TLS_SNI_HOSTNAME_MAX + 1];
	size_t length = evbuffer_get_length(buffev->input);
	const unsigned char *bytes = evbuffer_pullup(buffev->input, length);
	if (length && !bytes) {
		redsocks_drop_client(client);
		return;
	}
	redsocks_touch_client(client);
	tls_sni_result result = tls_sni_parse(bytes, length, hostname);
	if (result == TLS_SNI_FOUND)
		httpc_choose_target(client, hostname, NULL);
	else if (result == TLS_SNI_INVALID)
		httpc_choose_target(client, NULL, "invalid_client_hello");
	else if (result == TLS_SNI_NO_SNI)
		httpc_choose_target(client, NULL, length && bytes[0] != 22 ? "non_tls" : "no_sni");
	else if (length >= TLS_SNI_PROBE_MAX)
		httpc_choose_target(client, NULL, "probe_limit");
}

static void httpc_probe_timeout_cb(int fd, short what, void *_arg)
{
	redsocks_client *client = _arg;
	httpc_client *data = red_payload(client);
	data->timer_active = false;
	httpc_choose_target(client, NULL, "probe_timeout");
}

static void httpc_probe_error_cb(struct bufferevent *buffev, short what, void *_arg)
{
	redsocks_client *client = _arg;
	redsocks_log_error(client, LOG_INFO, "HTTP CONNECT probe stopped reason=%s",
		(what & EVBUFFER_EOF) ? "client_eof" : "client_error");
	redsocks_drop_client(client);
}

static void httpc_connect_relay(redsocks_client *client)
{
	httpc_client *data = red_payload(client);
	struct timeval now, elapsed, deadline = { 1, 0 }, remaining;
	data->original_errorcb = client->client->errorcb;
	client->client->readcb = httpc_probe_read_cb;
	client->client->errorcb = httpc_probe_error_cb;
	bufferevent_setwatermark(client->client, EV_READ, 1, TLS_SNI_PROBE_MAX);
	if (redsocks_gettimeofday(&now) != 0) {
		httpc_choose_target(client, NULL, "probe_clock_error");
		return;
	}
	timersub(&now, &client->first_event, &elapsed);
	if (timercmp(&elapsed, &deadline, >=)) {
		httpc_choose_target(client, NULL, "probe_timeout");
		return;
	}
	timersub(&deadline, &elapsed, &remaining);
	evtimer_set(&data->probe_timer, httpc_probe_timeout_cb, client);
	if (evtimer_add(&data->probe_timer, &remaining) != 0) {
		redsocks_log_errno(client, LOG_ERR, "evtimer_add");
		redsocks_drop_client(client);
		return;
	}
	data->timer_active = true;
}


static void httpc_client_init(redsocks_client *client)
{
	client->state = httpc_new;
}

static void httpc_instance_fini(redsocks_instance *instance)
{
	http_auth *auth = red_http_auth(instance);
	free(auth->last_auth_query);
	auth->last_auth_query = NULL;
}

static struct evbuffer *httpc_mkconnect(redsocks_client *client);

extern const char *auth_request_header;
extern const char *auth_response_header;

/* The whole header block must arrive before parsing 407. Reading its first
 * line early used to lose a fragmented Proxy-Authenticate header. */
static char *httpc_auth_challenge(char *headers)
{
	char *line = strchr(headers, '\n');
	while (line && *++line) {
		char *next = strchr(line, '\n');
		if (!next)
			break;
		*next = '\0';
		if (next > line && next[-1] == '\r')
			next[-1] = '\0';
		if (strncasecmp(line, auth_request_header, strlen(auth_request_header)) == 0) {
			char *value = line + strlen(auth_request_header);
			while (isspace((unsigned char)*value))
				++value;
			if (strncasecmp(value, "Basic ", 6) == 0 || strncasecmp(value, "Digest ", 7) == 0)
				return strdup(value);
		}
		line = next;
	}
	return NULL;
}

static void httpc_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	httpc_client *data = red_payload(client);
	size_t length = evbuffer_get_length(buffev->input), delimiter = 4;
	assert(client->relay == buffev);
	assert(client->state == httpc_request_sent);
	redsocks_touch_client(client);

	struct evbuffer_ptr end = evbuffer_search(buffev->input, "\r\n\r\n", 4, NULL);
	if (end.pos < 0) {
		end = evbuffer_search(buffev->input, "\n\n", 2, NULL);
		delimiter = 2;
	}
	if (end.pos < 0) {
		if (length >= HTTP_HEAD_WM_HIGH) {
			redsocks_log_error(client, LOG_NOTICE, "HTTP CONNECT target=%s status=oversized_headers", data->authority);
			redsocks_drop_client(client);
		}
		return;
	}
	size_t headers_length = (size_t)end.pos + delimiter;
	if (headers_length > HTTP_HEAD_WM_HIGH) {
		redsocks_drop_client(client);
		return;
	}
	char *headers = malloc(headers_length + 1);
	if (!headers) {
		redsocks_drop_client(client);
		return;
	}
	evbuffer_copyout(buffev->input, headers, headers_length);
	headers[headers_length] = '\0';
	unsigned int code = 0;
	if (memchr(headers, '\0', headers_length) ||
		sscanf(headers, "HTTP/%*u.%*u %u", &code) != 1 || code < 100 || code > 599)
		code = 0;
	redsocks_log_error(client, code >= 200 && code <= 299 ? LOG_INFO : LOG_NOTICE,
		"HTTP CONNECT target=%s status=%u", data->authority, code);

	if (code == 407 && data->auth_retries == 0 &&
		client->instance->config.login && client->instance->config.password) {
		char *challenge = httpc_auth_challenge(headers);
		if (challenge) {
			http_auth *auth = red_http_auth(client->instance);
			free(auth->last_auth_query);
			auth->last_auth_query = challenge;
			auth->last_auth_count = 0;
			++data->auth_retries;
			free(headers);
			redsocks_bufferevent_free(client->relay);
			client->relay = NULL;
			client->state = httpc_new;
			/* Frozen authority and original client input survive reconnection. */
			redsocks_connect_relay(client);
			return;
		}
	}
	free(headers);

	if (code >= 200 && code <= 299) {
		evbuffer_drain(buffev->input, headers_length);
		/* Move the original bytes exactly once, only after final 2xx headers.
		 * Both the buffer and splice pumps drain relay->output first. */
		if (bufferevent_write_buffer(client->relay, client->client->input) != 0)
			goto fail;
	} else if (client->instance->config.on_proxy_fail == ONFAIL_FORWARD_HTTP_ERR) {
		evbuffer_drain(client->client->input, evbuffer_get_length(client->client->input));
		redsocks_shutdown(client, client->client, SHUT_RD);
		redsocks_shutdown(client, client->relay, SHUT_WR);
	} else {
		goto fail;
	}
	/* Include any bytes already received after the response headers, rather
	 * than waiting for a new socket read to wake the buffer pump. */
	if (bufferevent_write_buffer(client->client, client->relay->input) != 0)
		goto fail;
	client->state = httpc_headers_skipped;
	redsocks_start_relay(client); /* may free client */
	return;

fail:
	redsocks_drop_client(client);
}

static struct evbuffer *httpc_mkconnect(redsocks_client *client)
{
	struct evbuffer *buff = NULL, *retval = NULL;
	char *auth_string = NULL;
	int len;

	buff = evbuffer_new();
	if (!buff) {
		redsocks_log_errno(client, LOG_ERR, "evbuffer_new");
		goto fail;
	}

	http_auth *auth = red_http_auth(client->instance);
	++auth->last_auth_count;

	const char *auth_scheme = NULL;

	if (auth->last_auth_query != NULL) {
		/* find previous auth challange */

		if (strncasecmp(auth->last_auth_query, "Basic", 5) == 0) {
			auth_string = basic_authentication_encode(client->instance->config.login, client->instance->config.password);
			auth_scheme = "Basic";
		} else if (strncasecmp(auth->last_auth_query, "Digest", 6) == 0) {
			const char *uri = ((httpc_client *)red_payload(client))->authority;

			/* prepare an random string for cnounce */
			char cnounce[17];
			snprintf(cnounce, sizeof(cnounce), "%08x%08x", red_randui32(), red_randui32());

			auth_string = digest_authentication_encode(auth->last_auth_query + 7, //line
					client->instance->config.login, client->instance->config.password, //user, pass
					"CONNECT", uri, auth->last_auth_count, cnounce); // method, path, nc, cnounce
			auth_scheme = "Digest";
		}
	} else if (client->instance->config.login && client->instance->config.password) {
		/* Preserve ProxyDroid's preemptive Basic behavior for existing profiles. */
		auth_string = basic_authentication_encode(client->instance->config.login, client->instance->config.password);
		auth_scheme = "Basic";
	}

	// TODO: do accurate evbuffer_expand() while cleaning up http-auth
	len = evbuffer_add_printf(buff, "CONNECT %s HTTP/1.0\r\n",
		((httpc_client *)red_payload(client))->authority);
	if (len < 0) {
		redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
		goto fail;
	}

	if (auth_string) {
		len = evbuffer_add_printf(buff, "%s %s %s\r\n",
			auth_response_header, auth_scheme, auth_string);
		if (len < 0) {
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
		free(auth_string);
		auth_string = NULL;
	}

	const enum disclose_src_e disclose_src = client->instance->config.disclose_src;
	if (disclose_src != DISCLOSE_NONE) {
		char clientip[INET_ADDRSTRLEN];
		const char *ip = inet_ntop(client->clientaddr.sin_family, &client->clientaddr.sin_addr, clientip, sizeof(clientip));
		if (!ip) {
			redsocks_log_errno(client, LOG_ERR, "inet_ntop");
			goto fail;
		}
		if (disclose_src == DISCLOSE_X_FORWARDED_FOR) {
			len = evbuffer_add_printf(buff, "X-Forwarded-For: %s\r\n", ip);
		} else if (disclose_src == DISCLOSE_FORWARDED_IP) {
			len = evbuffer_add_printf(buff, "Forwarded: for=%s\r\n", ip);
		} else if (disclose_src == DISCLOSE_FORWARDED_IPPORT) {
			len = evbuffer_add_printf(buff, "Forwarded: for=\"%s:%d\"\r\n", ip,
				ntohs(client->clientaddr.sin_port));
		}
		if (len < 0) {
			redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
			goto fail;
		}
	}

	len = evbuffer_add(buff, "\r\n", 2);
	if (len < 0) {
		redsocks_log_errno(client, LOG_ERR, "evbufer_add");
		goto fail;
	}

	retval = buff;
	buff = NULL;

fail:
	if (auth_string)
		free(auth_string);
	if (buff)
		evbuffer_free(buff);
	return retval;
}


static void httpc_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	redsocks_touch_client(client);

	if (client->state == httpc_new) {
		redsocks_write_helper_ex(
			buffev, client,
			httpc_mkconnect, httpc_request_sent, 1, HTTP_HEAD_WM_HIGH
			);
	}
	else if (client->state >= httpc_request_sent) {
		bufferevent_disable(buffev, EV_WRITE);
	}
}


relay_subsys http_connect_subsys =
{
	.name                 = "http-connect",
	.payload_len          = sizeof(httpc_client),
	.instance_payload_len = sizeof(http_auth),
	.readcb               = httpc_read_cb,
	.writecb              = httpc_write_cb,
	.init                 = httpc_client_init,
	.fini                 = httpc_client_fini,
	.connect_relay        = httpc_connect_relay,
	.instance_fini        = httpc_instance_fini,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
