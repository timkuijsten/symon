/*
 * Copyright (c) 2024 Tim Kuijsten
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "symon.h"
#include "xmalloc.h"

#define CONNSAMPLES 12 /* number of samples per connection */

enum states { connunknown, connconnecting };
struct peerinfo {
	struct tcp_info tcpnfo;
	struct stream *st;
	const char *header;
	size_t headerlen;
	char *host, *port;
	int s;
	int sample;
	uint16_t errors;
	enum states state;
};

/* these strings are repeated if less than CONNSAMPLES long */
static const char sshstr[] = "SSH-2.0-systrend_0.1";
static const char htpstr[] = "GET / HTTP/1.0\r\n";
static const char tlsstr[] = "\x03\x04RaNdOm-systrend"; /* 0x0304; TLS v1.3 */
static struct peerinfo *peerinfo;
static size_t peerinfocnt;
static int iter;

/*
 * Return socket fd on success, -1 on error with errno set.
 */
static int
startconnecting(const char *name, const char *serv)
{
	struct addrinfo hints, *res0, *res;
	const char *cause = NULL;
	int flags, e, s, save_errno;

	memset(&hints, 0x00, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;

	e = getaddrinfo(name, serv, &hints, &res0);
	if (e != 0) {
		warning("%s:%s getaddrinfo %s", name, serv, gai_strerror(e));
		return -1;
	}

	s = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		flags = fcntl(s, F_GETFL);
		if (flags == -1) {
			cause = "f_getfl";
			save_errno = errno;
			close(s);
			s = -1;
			errno = save_errno;
			continue;
		}
		if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
			cause = "f_setfl";
			save_errno = errno;
			close(s);
			s = -1;
			errno = save_errno;
			continue;
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			if (errno != EINPROGRESS) {
				cause = "connect";
				save_errno = errno;
				close(s);
				s = -1;
				errno = save_errno;
				continue;
			}
		}

		break;
	}

	freeaddrinfo(res0);

	if (s == -1) {
		warning("%s:%s %s %s", name, serv, cause, strerror(errno));
		return -1;
	}

	return s;
}

void
init_rtt(struct stream *st)
{
	struct peerinfo *pi;
	const char *p = NULL;

	peerinfocnt++;
	if (peerinfocnt > SYMON_MAX_DOBJECTS)
		fatal("%s:%d: dynamic object limit (%d) exceeded", __FILE__,
		    __LINE__, SYMON_MAX_DOBJECTS);
	if (sizeof(*peerinfo) > SYMON_MAX_OBJSIZE)
		fatal("%s:%d: dynamic object limit (%d) exceeded for peerinfo "
		    "structures", __FILE__, __LINE__, SYMON_MAX_OBJSIZE);

	peerinfo = xreallocarray(peerinfo, peerinfocnt, sizeof(*peerinfo));
	pi = &peerinfo[peerinfocnt - 1];
	memset(pi, 0, sizeof(*pi));
	pi->st = st;

	/* split arg on host + port */
	p = strrchr(st->arg, ':');
	if (p == NULL)
		fatal("%s: could not find colon for port", st->arg);

	if (strlen(p) == 1)
		fatal("%s: port empty", st->arg);

	pi->host = strndup(st->arg, p - st->arg);
	if (pi->host == NULL)
		fatal("%s: strndup host %s", st->arg, strerror(errno));

	pi->port = strdup(p + 1);
	if (pi->port == NULL)
		fatal("%s: strdup port %s", st->arg, strerror(errno));

	if (strcmp(pi->port, "22") == 0 ) {
		pi->header = sshstr;
		pi->headerlen = strlen(sshstr);
	} else if (strcmp(pi->port, "80") == 0 ) {
		pi->header = htpstr;
		pi->headerlen = strlen(htpstr);
	} else {
		pi->header = tlsstr;
		pi->headerlen = strlen(tlsstr);
	}
	pi->state = connunknown;
	pi->sample = 0;
	pi->s = startconnecting(pi->host, pi->port);
	if (pi->s == -1) {
		warning("failed connecting to %s", st->arg);
	} else {
		pi->state = connconnecting;
	}

	info("started module rtt(%.200s)", st->arg);
}

void
gets_rtt(void)
{
	iter++;
}

int
get_rtt(char *symon_buf, int maxlen, struct stream *st)
{
	struct peerinfo *pi;
	socklen_t sl;
	size_t i;
	int n;

	pi = NULL;
	for (i = 0; i < peerinfocnt; i++)
		if (peerinfo[i].st == st) {
			pi = &peerinfo[i];
			break;
		}

	if (pi == NULL)
		fatal("%s: peer not found", st->arg);

	switch (pi->state) {
	case connunknown:
		if (iter % CONNSAMPLES != 1)
			goto out;

		pi->sample = 0;
		pi->s = startconnecting(pi->host, pi->port);
		if (pi->s == -1)
			return 0;

		pi->state = connconnecting;
		/* try to send data in next call */
		return 0;
	case connconnecting:
		n = write(pi->s, &pi->header[pi->sample % pi->headerlen], 1);
		if (n == -1) {
			if (errno == EWOULDBLOCK && iter % CONNSAMPLES != 0)
				return 0; /* not connected yet */

			warning("%s write %s", st->arg, strerror(errno));
			goto err;
		}
		pi->sample++;

		sl = sizeof(pi->tcpnfo);
		// TODO EINTR
		if (getsockopt(pi->s, 6, TCP_INFO, &pi->tcpnfo, &sl) == -1) {
			warning("%s TCP_INFO %s", st->arg, strerror(errno));
			goto err;
		}
		debug("%s\trtt %d\tvar %d",
		    pi->st->arg,
		    pi->tcpnfo.tcpi_rtt,
		    pi->tcpnfo.tcpi_rttvar);

		if (iter % CONNSAMPLES == 0) {
			/*
			 * Start a new connection, but even if the new
			 * connection fails, we still want to send the data of
			 * this round, so goto out.
			 */
			close(pi->s);
			pi->state = connunknown;
			pi->sample = 0;
			pi->s = startconnecting(pi->host, pi->port);
			if (pi->s == -1)
				goto out;

			pi->state = connconnecting;
		}
		goto out;
	default:
		fatal("%s: unexpected state %d", st->arg, pi->state);
	}

err:
	close(pi->s);
	pi->s = -1;
	pi->errors++;
	pi->tcpnfo.tcpi_rtt = 0;
	pi->tcpnfo.tcpi_rttvar = 0;
	pi->state = connunknown;
	return 0;
out:
	return snpack(symon_buf, maxlen, st->arg, MT_RTT,
	    pi->tcpnfo.tcpi_rtt,
	    pi->tcpnfo.tcpi_rttvar,
	    pi->errors);
}
