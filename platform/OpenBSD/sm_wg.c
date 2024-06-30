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

/*
 * Get the current WireGuard peer statistics from the kernel and return them in
 * symon_buf as
 *
 * total bytes received : total bytes transmitted : last handshake
 */

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_wg.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"
#include "error.h"
#include "symon.h"
#include "xmalloc.h"

static struct wg_data_io *wg_stats;
static size_t wg_stats_count;
static int sock = -1;

void
init_wg(struct stream *st)
{
	struct wg_interface_io *wg_interface;
	struct wg_data_io      *wgdata;
	struct wg_peer_io      *wg_peer;
	struct wg_aip_io       *wg_aip;
	char *peerdesc;
	size_t i;

	/* we only need one socket for all peers */
	if (sock == -1) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == -1)
			fatal("socket");
	}

	/* split arg on interface name and peer description */
	peerdesc = strchr(st->arg, ':');
	if (peerdesc == NULL)
		fatal("could not find colon after interface name: %s", st->arg);

	*peerdesc = '\0';
	peerdesc++;
	if (strlen(peerdesc) == 0)
		fatal("peer description empty: %s", st->arg);

	wgdata = NULL;
	for (i = 0; i < wg_stats_count; i++) {
		if (strcmp(wg_stats[i].wgd_name, st->arg) == 0) {
			wgdata = &wg_stats[i];
			break;
		}
	}

	if (wgdata == NULL) {
		debug("create %s", st->arg);
		wg_stats_count++;
		wg_stats = xreallocarray(wg_stats, wg_stats_count,
		    sizeof(*wg_stats));
		wgdata = &wg_stats[wg_stats_count-1];
		strlcpy(wgdata->wgd_name, st->arg, sizeof(wgdata->wgd_name));
		wgdata->wgd_size = 0;
		wgdata->wgd_interface = NULL;

		/* fill data so we can verify the peer exists */
		gets_wg();
	}

	info("started module wg(%.200s:%s)", st->arg, peerdesc);

	wg_interface = wgdata->wgd_interface;
	if (wg_interface == NULL)
		fatal("init_wg: %s not found", st->arg);

	wg_peer = &wg_interface->i_peers[0];
	for (i = 0; i < wg_interface->i_peers_count; i++) {
		if (strcmp(wg_peer->p_description, peerdesc) == 0)
			return;

		wg_aip = &wg_peer->p_aips[0];
		wg_aip += wg_peer->p_aips_count;
		wg_peer = (struct wg_peer_io *)wg_aip;
	}

	fatal("%s:%s does not exist", st->arg, peerdesc);
}

void
gets_wg(void)
{
	struct wg_data_io *wgdata;
	size_t i, last_size;

	for (i = 0; i < wg_stats_count; i++) {
		wgdata = &wg_stats[i];
		for (last_size = wgdata->wgd_size;; last_size = wgdata->wgd_size) {
			if (ioctl(sock, SIOCGWG, wgdata) == -1) {
				warning("%s: SIOCGWG", wgdata->wgd_name);
				break;
			}

			if (last_size >= wgdata->wgd_size)
				break;

			if (wgdata->wgd_size > SYMON_MAX_DOBJECTS)
				fatal("%s:%d: dynamic object limit (%d) "
				    "exceeded for wg_data_io structures",
				    __FILE__, __LINE__, SYMON_MAX_DOBJECTS);

			wgdata->wgd_interface = xrealloc(wgdata->wgd_interface,
			    wgdata->wgd_size);
			debug("%s %zu bytes", wgdata->wgd_name, wgdata->wgd_size);
		}
	}
}

int
get_wg(char *symon_buf, int maxlen, struct stream *st)
{
	struct wg_interface_io *wg_interface;
	struct wg_peer_io      *wg_peer;
	struct wg_aip_io       *wg_aip;
	const char *peerdesc;
	char nam[10];
	size_t i;

	peerdesc = &st->arg[strlen(st->arg)] + 1;

	wg_interface = NULL;
	for (i = 0; i < wg_stats_count; i++) {
		if (strcmp(wg_stats[i].wgd_name, st->arg) == 0) {
			wg_interface = wg_stats[i].wgd_interface;
			break;
		}
	}

	if (wg_interface == NULL) {
		warning("get_wg: %s not found", st->arg);
		return 0;
	}

	snprintf(nam, sizeof(nam), "%s:%s", st->arg, peerdesc);
	wg_peer = &wg_interface->i_peers[0];
	for (i = 0; i < wg_interface->i_peers_count; i++) {
		if (strcmp(wg_peer->p_description, peerdesc) != 0) {
			wg_aip = &wg_peer->p_aips[0];
			wg_aip += wg_peer->p_aips_count;
			wg_peer = (struct wg_peer_io *)wg_aip;
			continue;
		}

		return snpack(symon_buf, maxlen, nam, MT_WG,
		    wg_peer->p_rxbytes,
		    wg_peer->p_txbytes,
		    wg_peer->p_last_handshake.tv_sec);
	}

	warning("couldn't find peer with description \"%s\" on %s", peerdesc,
	    st->arg);

	return 0;
}
