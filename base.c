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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#if defined USE_IPTABLES
# include <limits.h>
# include <linux/netfilter_ipv4.h>
#endif
#if defined USE_PF
# include <net/if.h>
# include <net/pfvar.h>
# include <sys/ioctl.h>
# include <errno.h>
#endif
#include "log.h"
#include "main.h"
#include "parser.h"
#include "redsocks.h"

typedef struct redirector_subsys_t {
	int (*init)();
	void (*fini)();
	int (*getdestaddr)(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr);
	const char *name;
	// some subsystems may store data here:
	int private;
} redirector_subsys;

typedef struct base_instance_t {
	int configured;
	char *chroot;
	char *user;
	char *group;
	char *redirector_name;
	redirector_subsys *redirector;
	char *log_name;
	bool log_debug;
	bool log_info;
	bool daemon;
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	uint16_t tcp_keepalive_time;
	uint16_t tcp_keepalive_probes;
	uint16_t tcp_keepalive_intvl;
#endif
	uint32_t rlimit_nofile;
	uint32_t redsocks_conn_max;
	uint32_t connpres_idle_timeout;
	uint32_t max_accept_backoff_ms;
} base_instance;

static base_instance instance;

#if defined __FreeBSD__ || defined USE_PF
static int redir_open_private(const char *fname, int flags)
{
	int fd = open(fname, flags);
	if (fd < 0) {
		log_errno(LOG_ERR, "open(%s)", fname);
		return -1;
	}
	instance.redirector->private = fd;
	return 0;
}

static void redir_close_private()
{
	close(instance.redirector->private);
	instance.redirector->private = -1;
}
#endif

#ifdef __FreeBSD__
static int redir_init_ipf()
{
#ifdef IPNAT_NAME
	const char *fname = IPNAT_NAME;
#else
	const char *fname = IPL_NAME;
#endif
	return redir_open_private(fname, O_RDONLY);
}

static int getdestaddr_ipf(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	int natfd = instance.redirector->private;
	struct natlookup natLookup;
	int x;
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	struct ipfobj obj;
#else
	static int siocgnatl_cmd = SIOCGNATL & 0xff;
#endif

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(natLookup);
	obj.ipfo_ptr = &natLookup;
	obj.ipfo_type = IPFOBJ_NATLOOKUP;
	obj.ipfo_offset = 0;
#endif

	natLookup.nl_inport = bindaddr->sin_port;
	natLookup.nl_outport = client->sin_port;
	natLookup.nl_inip = bindaddr->sin_addr;
	natLookup.nl_outip = client->sin_addr;
	natLookup.nl_flags = IPN_TCP;
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	x = ioctl(natfd, SIOCGNATL, &obj);
#else
	/*
	 * IP-Filter changed the type for SIOCGNATL between
	 * 3.3 and 3.4.  It also changed the cmd value for
	 * SIOCGNATL, so at least we can detect it.  We could
	 * put something in configure and use ifdefs here, but
	 * this seems simpler.
	 */
	if (63 == siocgnatl_cmd) {
		struct natlookup *nlp = &natLookup;
		x = ioctl(natfd, SIOCGNATL, &nlp);
	} else {
		x = ioctl(natfd, SIOCGNATL, &natLookup);
	}
#endif
	if (x < 0) {
		if (errno != ESRCH)
			log_errno(LOG_WARNING, "ioctl(SIOCGNATL)\n");
		return -1;
	} else {
		destaddr->sin_family = AF_INET;
		destaddr->sin_port = natLookup.nl_realport;
		destaddr->sin_addr = natLookup.nl_realip;
		return 0;
	}
}
#endif

#ifdef USE_PF
static int redir_init_pf()
{
	return redir_open_private("/dev/pf", O_RDWR);
}

static int getdestaddr_pf(
		int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr,
		struct sockaddr_in *destaddr)
{
	int pffd = instance.redirector->private;
	struct pfioc_natlook nl;
	int saved_errno;
	char clientaddr_str[INET6_ADDRSTRLEN], bindaddr_str[INET6_ADDRSTRLEN];

	memset(&nl, 0, sizeof(struct pfioc_natlook));
	nl.saddr.v4.s_addr = client->sin_addr.s_addr;
	nl.sport = client->sin_port;
	nl.daddr.v4.s_addr = bindaddr->sin_addr.s_addr;
	nl.dport = bindaddr->sin_port;
	nl.af = AF_INET;
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;

	if (ioctl(pffd, DIOCNATLOOK, &nl) != 0) {
		if (errno == ENOENT) {
			nl.direction = PF_IN; // required to redirect local packets
			if (ioctl(pffd, DIOCNATLOOK, &nl) != 0) {
				goto fail;
			}
		}
		else {
			goto fail;
		}
	}
	destaddr->sin_family = AF_INET;
	destaddr->sin_port = nl.rdport;
	destaddr->sin_addr = nl.rdaddr.v4;
	return 0;

fail:
	saved_errno = errno;
	if (!inet_ntop(client->sin_family, &client->sin_addr, clientaddr_str, sizeof(clientaddr_str)))
		strncpy(clientaddr_str, "???", sizeof(clientaddr_str));
	if (!inet_ntop(bindaddr->sin_family, &bindaddr->sin_addr, bindaddr_str, sizeof(bindaddr_str)))
		strncpy(bindaddr_str, "???", sizeof(bindaddr_str));

	errno = saved_errno;
	log_errno(LOG_WARNING, "ioctl(DIOCNATLOOK {src=%s:%d, dst=%s:%d})",
			  clientaddr_str, ntohs(nl.sport), bindaddr_str, ntohs(nl.dport));
	return -1;
}
#endif

#ifdef USE_IPTABLES
static int getdestaddr_iptables(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

	error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
	if (error) {
		log_errno(LOG_WARNING, "getsockopt");
		return -1;
	}
	return 0;
}
#endif

static int getdestaddr_generic(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

	error = getsockname(fd, (struct sockaddr*)destaddr, &socklen);
	if (error) {
		log_errno(LOG_WARNING, "getsockopt");
		return -1;
	}
	return 0;
}

int getdestaddr(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	return instance.redirector->getdestaddr(fd, client, bindaddr, destaddr);
}

int apply_tcp_keepalive(int fd)
{
	struct { int level, option, value; } opt[] = {
		{ SOL_SOCKET, SO_KEEPALIVE, 1 },
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
		{ IPPROTO_TCP, TCP_KEEPIDLE, instance.tcp_keepalive_time },
		{ IPPROTO_TCP, TCP_KEEPCNT, instance.tcp_keepalive_probes },
		{ IPPROTO_TCP, TCP_KEEPINTVL, instance.tcp_keepalive_intvl },
#endif
	};
	for (int i = 0; i < SIZEOF_ARRAY(opt); ++i) {
		if (opt[i].value) {
			int error = setsockopt(fd, opt[i].level, opt[i].option, &opt[i].value, sizeof(opt[i].value));
			if (error) {
				log_errno(LOG_WARNING, "setsockopt(%d, %d, %d, &%d, %zu)", fd, opt[i].level, opt[i].option, opt[i].value, sizeof(opt[i].value));
				return -1;
			}
		}
	}
	return 0;
}

uint32_t max_accept_backoff_ms()
{
	return instance.max_accept_backoff_ms;
}

uint32_t redsocks_conn_max()
{
	return instance.redsocks_conn_max;
}

uint32_t connpres_idle_timeout()
{
	return instance.connpres_idle_timeout;
}

static redirector_subsys redirector_subsystems[] =
{
#ifdef __FreeBSD__
	{ .name = "ipf", .init = redir_init_ipf, .fini = redir_close_private, .getdestaddr = getdestaddr_ipf },
#endif
#ifdef USE_PF
	{ .name = "pf",  .init = redir_init_pf,  .fini = redir_close_private, .getdestaddr = getdestaddr_pf },
#endif
#ifdef USE_IPTABLES
	{ .name = "iptables", .getdestaddr = getdestaddr_iptables },
#endif
	{ .name = "generic",  .getdestaddr = getdestaddr_generic  },
};

/***********************************************************************
 * `base` config parsing
 */
static parser_entry base_entries[] =
{
	{ .key = "chroot",     .type = pt_pchar,   .addr = &instance.chroot },
	{ .key = "user",       .type = pt_pchar,   .addr = &instance.user },
	{ .key = "group",      .type = pt_pchar,   .addr = &instance.group },
	{ .key = "redirector", .type = pt_pchar,   .addr = &instance.redirector_name },
	{ .key = "log",        .type = pt_pchar,   .addr = &instance.log_name },
	{ .key = "log_debug",  .type = pt_bool,    .addr = &instance.log_debug },
	{ .key = "log_info",   .type = pt_bool,    .addr = &instance.log_info },
	{ .key = "daemon",     .type = pt_bool,    .addr = &instance.daemon },
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	{ .key = "tcp_keepalive_time",   .type = pt_uint16, .addr = &instance.tcp_keepalive_time },
	{ .key = "tcp_keepalive_probes", .type = pt_uint16, .addr = &instance.tcp_keepalive_probes },
	{ .key = "tcp_keepalive_intvl",  .type = pt_uint16, .addr = &instance.tcp_keepalive_intvl },
#endif
	{ .key = "rlimit_nofile", .type = pt_uint32, .addr = &instance.rlimit_nofile },
	{ .key = "redsocks_conn_max", .type = pt_uint32, .addr = &instance.redsocks_conn_max },
	{ .key = "connpres_idle_timeout", .type = pt_uint32, .addr = &instance.connpres_idle_timeout },
	{ .key = "max_accept_backoff", .type = pt_uint32, .addr = &instance.max_accept_backoff_ms },
	{ }
};

static int base_onenter(parser_section *section)
{
	if (instance.configured) {
		parser_error(section->context, "only one instance of base is valid");
		return -1;
	}
	memset(&instance, 0, sizeof(instance));
	instance.configured = 1;
	instance.max_accept_backoff_ms = 60000;
	instance.connpres_idle_timeout = 7440;
	return 0;
}

static int base_onexit(parser_section *section)
{
	if (!instance.max_accept_backoff_ms) {
		parser_error(section->context, "`max_accept_backoff` must be positive, 0 ms is too low");
		return -1;
	}

	if (instance.redirector_name) {
		redirector_subsys *ss;
		FOREACH(ss, redirector_subsystems) {
			if (!strcmp(ss->name, instance.redirector_name)) {
				instance.redirector = ss;
				instance.redirector->private = -1;
				break;
			}
		}
		if (!instance.redirector) {
			parser_error(section->context, "invalid `redirector` set <%s>", instance.redirector_name);
			return -1;
		}
	}
	else {
		parser_error(section->context, "no `redirector` set");
		return -1;
	}

	return 0;
}

static parser_section base_conf_section =
{
	.name    = "base",
	.entries = base_entries,
	.onenter = base_onenter,
	.onexit  = base_onexit
};

/***********************************************************************
 * `base` initialization
 */
static int base_init(struct event_base *evbase)
{
	UNUSED(evbase);
	if (!instance.configured || !instance.redirector) return -1;
	/* A library must never change its host process identity or environment. */
	if (instance.daemon || instance.chroot || instance.user || instance.group || instance.rlimit_nofile) {
		log_error(LOG_ERR, "daemon, chroot, user, group and rlimit_nofile are unavailable in library mode");
		return -1;
	}
	if (instance.redirector->init && instance.redirector->init() < 0) return -1;
	struct rlimit limit;
	if (getrlimit(RLIMIT_NOFILE, &limit)) return -1;
	instance.rlimit_nofile = limit.rlim_cur > UINT32_MAX ? UINT32_MAX : limit.rlim_cur;
	if (!instance.redsocks_conn_max)
		instance.redsocks_conn_max = (instance.rlimit_nofile - instance.rlimit_nofile / 4) /
			(redsocks_has_splice_instance() ? 6 : 2);
	if (log_preopen(instance.log_name ? instance.log_name : "stderr", instance.log_debug, instance.log_info)) return -1;
	log_open();
	return 0;
}

static int base_fini()
{
	if (instance.redirector && instance.redirector->fini)
		instance.redirector->fini();

	free(instance.chroot);
	free(instance.user);
	free(instance.group);
	free(instance.redirector_name);
	free(instance.log_name);

	memset(&instance, 0, sizeof(instance));

	return 0;
}

app_subsys base_subsys =
{
	.init = base_init,
	.fini = base_fini,
	.conf_section = &base_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
