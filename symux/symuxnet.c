/*
 * Copyright (c) 2001-2007 Willem Dijkstra
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include "conf.h"
#include "data.h"
#include "error.h"
#include "symux.h"
#include "symuxnet.h"
#include "net.h"
#include "xmalloc.h"
#include "share.h"

__BEGIN_DECLS
int check_crc_packet(struct symonpacket *);
__END_DECLS

/*
 * Create non-blocking UDP and/or TCP listening sockets for addr:port and append
 * them to slist. scnt should countain the current number of sockets in slist.
 * Both slist and scnt are updated for every newly appended socket. If addr is
 * NULL the wildcard address will be used. socktype must be 0 or one of
 * SOCK_DGRAM or SOCK_STREAM.
 * Returns the number of created sockets on success, 0 on failure.
 */
int
create_listeners(int **slist, size_t *scnt, char *addr, char *port,
    int socktype)
{
    struct addrinfo hints, *res0, *res;
    int e, s, nsocks, one;

    if (port == NULL || strlen(port) == 0)
        fatal("configure a mux port");

    /* generate the udp listen socket specified in the mux statement */
    memset(&hints, 0x00, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;

    if (addr != NULL && strcmp(addr, "*") == 0)
        addr = NULL;

    e = getaddrinfo(addr, port, &hints, &res0);
    if (addr == NULL) /* set for debug message */
        addr = "*";

    if (e != 0) {
        warning("%s:%s getaddrinfo %s", addr, port, gai_strerror(e));
        return 0;
    }

    nsocks = 0;
    for (res = res0; res != NULL; res = res->ai_next) {
        s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s == -1) {
            warning("%s:%s socket error %s", addr, port, strerror(errno));
            continue;
        }

        e = fcntl(s, F_GETFD, 0);
        e = fcntl(s, F_SETFD, e | O_NONBLOCK);
        if (e == -1)
            fatal("%s:%s could not set socket to non-blocking i/o: %.200s",
                addr, port, strerror(errno));

        one = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
            warning("%s:%s could not set SO_REUSEADDR option: %s", addr, port,
                strerror(errno));

        if (bind(s, res->ai_addr, res->ai_addrlen) == -1)
            fatal("%s:%s bind error: %s", addr, port, strerror(errno));

        if (res->ai_socktype == SOCK_STREAM) {
            if (listen(s, SYMUX_TCPBACKLOG) == -1)
                fatal("%s:%s tcp listen error: %s", addr, port, strerror(errno));
        }

        *slist = xreallocarray(*slist, *scnt + 1, sizeof(int));
        (*slist)[(*scnt)++] = s;

        info("listening for incoming connections on %s:%s:%s",
            res->ai_socktype == SOCK_STREAM ? "tcp" : "udp", addr, port);

        nsocks++;
    }

    freeaddrinfo(res0);

    return nsocks;
}

/*
 * Wait for traffic (symon reports from a source in sourclist | clients trying to connect
 * Returns the <source> and <packet>
 * Silently forks off clienthandlers
 */
void
wait_for_traffic(struct mux * mux, struct source ** source)
{
    fd_set readset;
    int i;
    int socksactive;
    int maxsock;

    for (;;) {                  /* FOREVER - until a valid symon packet is
                                 * received */
        FD_ZERO(&readset);

        maxsock = 0;

        for (i = 0; i < mux->clientsocketcnt; i++) {
            FD_SET(mux->clientsocket[i], &readset);
            if (maxsock < mux->clientsocket[i])
                maxsock = mux->clientsocket[i];
        }

        for (i = 0; i < mux->symonsocketcnt; i++) {
            FD_SET(mux->symonsocket[i], &readset);
            if (maxsock < mux->symonsocket[i])
                maxsock = mux->symonsocket[i];
        }

        maxsock++;
        socksactive = select(maxsock, &readset, NULL, NULL, NULL);

        if (socksactive != -1) {
            for (i = 0; i < mux->clientsocketcnt; i++)
                if (FD_ISSET(mux->clientsocket[i], &readset)) {
                    spawn_client(mux->clientsocket[i]);
                }

            for (i = 0; i < mux->symonsocketcnt; i++)
                if (FD_ISSET(mux->symonsocket[i], &readset)) {
                    if (recv_symon_packet(mux, mux->symonsocket[i], source))
                        return;
                }
        } else {
            if (errno == EINTR)
                return;         /* signal received while waiting, bail out */
        }
    }
}
/* Receive a symon packet for mux. Checks if the source is allowed and returns the source found.
 * return 0 if no valid packet found
 */
int
recv_symon_packet(struct mux * mux, int sock, struct source ** source)
{
    struct sockaddr_storage sind;
    socklen_t sl;
    int size, tries;
    unsigned int received;
    u_int32_t crc;

    received = 0;
    tries = 0;

    do {
        sl = sizeof(sind);

        size = recvfrom(sock,
                        (mux->packet.data + received),
                        (mux->packet.size - received),
                        0, (struct sockaddr *) &sind, &sl);
        if (size > 0)
            received += size;

        tries++;
    } while ((size == -1) &&
             (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) &&
             (tries < SYMUX_MAXREADTRIES) &&
             (received < mux->packet.size));

    if ((size == -1) &&
        errno) {
        warning("recvfrom failed: %.200s", strerror(errno));
        return 0;
    }

    *source = find_source_sockaddr(&mux->sol, (struct sockaddr *) &sind);

    get_numeric_name(&sind);

    if (*source == NULL) {
        debug("ignored data from %.200s:%.200s", res_host, res_service);
        return 0;
    } else {
        /* get header stream */
        mux->packet.offset = getheader(mux->packet.data, &mux->packet.header);
        /* check crc */
        crc = mux->packet.header.crc;
        mux->packet.header.crc = 0;
        setheader(mux->packet.data, &mux->packet.header);
        crc ^= crc32(mux->packet.data, received);
        if (crc != 0) {
            if (mux->packet.header.length > mux->packet.size)
                warning("ignored oversized packet from %.200s:%.200s; client and server have different stream configurations",
                        res_host, res_service);
            else
                warning("ignored packet with bad crc from %.200s:%.200s",
                        res_host, res_service);
            return 0;
        }
        /* check packet version */
        if (mux->packet.header.symon_version > SYMON_PACKET_VER) {
            warning("ignored packet with unsupported version %d from %.200s:%.200s",
                    mux->packet.header.symon_version, res_host, res_service);
            return 0;
        } else {
            if (flag_debug) {
                debug("good data received from %.200s:%.200s", res_host, res_service);
            }
            return 1;           /* good packet received */
        }
    }
}
int
accept_connection(int sock)
{
    struct sockaddr_storage sind;
    socklen_t len;
    int clientsock;

    bzero(&sind, sizeof(struct sockaddr_storage));
    len = sizeof(sind);

    if ((clientsock = accept(sock, (struct sockaddr *) &sind, &len)) < 0)
        fatal("failed to accept an incoming connection. (%.200s)",
              strerror(errno));

    get_numeric_name(&sind);

    return clientsock;
}
