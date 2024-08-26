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

#include <rrd.h>

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
 * Code moved here from main loop to end up with one idiomatic infinite network
 * loop.
 */
static void
handlemessage(struct symonpacket *packet, struct source *source, unsigned int *rrderrors)
{
    int maxstringlen;
    int offset;
    int slot;
    char *stringptr;
    char *arg_ra[4];
    char *stringbuf;
    struct stream *stream;
    time_t timestamp;
    struct packedstream ps;

    /*
     * Put information from packet into stringbuf (shared region).
     * Note that the stringbuf is used twice: 1) to update the
     * rrdfile and 2) to collect all the data from a single packet
     * that needs to shared to the clients. This is the reason for
     * the hasseling with stringptr.
     */

    offset = packet->offset;
    maxstringlen = shared_getmaxlen();
    /* put time:ip: into shared region */
    slot = master_forbidread();
    timestamp = (time_t) packet->header.timestamp;
    stringbuf = shared_getmem(slot);
    debug("stringbuf = 0x%08x", stringbuf);
    snprintf(stringbuf, maxstringlen, "%s;", source->addr);

    /* hide this string region from rrd update */
    maxstringlen -= strlen(stringbuf);
    stringptr = stringbuf + strlen(stringbuf);

    while (offset < packet->header.length) {
        bzero(&ps, sizeof(struct packedstream));
        if (packet->header.symon_version == 1) {
            offset += sunpack1(packet->data + offset, &ps);
        } else if (packet->header.symon_version == 2) {
            offset += sunpack2(packet->data + offset, &ps);
        } else {
            debug("unsupported packet version - ignoring data");
            ps.type = MT_EOT;
        }

        /* find stream in source */
        stream = find_source_stream(source, ps.type, ps.arg);

        if (stream != NULL) {
            /* put type and arg in and hide from rrd */
            snprintf(stringptr, maxstringlen, "%s:%s:", type2str(ps.type), ps.arg);
            maxstringlen -= strlen(stringptr);
            stringptr += strlen(stringptr);
            /* put timestamp in and show to rrd */
            snprintf(stringptr, maxstringlen, "%u", (unsigned int)timestamp);
            arg_ra[3] = stringptr;
            maxstringlen -= strlen(stringptr);
            stringptr += strlen(stringptr);

            /* put measurements in */
            ps2strn(&ps, stringptr, maxstringlen, PS2STR_RRD);

            if (stream->file != NULL) {
                /* clear optind for getopt call by rrdupdate */
                optind = 0;
                /* save if file specified */
                arg_ra[0] = "rrdupdate";
                arg_ra[1] = "--";
                arg_ra[2] = stream->file;

                /*
                 * This call will cost a lot (symux will become
                 * unresponsive and eat up massive amounts of cpu) if
                 * the rrdfile is out of sync.
                 */
                rrd_update(4, arg_ra);

                if (rrd_test_error()) {
                    if (*rrderrors < SYMUX_MAXRRDERRORS) {
                        (*rrderrors)++;
                        warning("rrd_update:%.200s", rrd_get_error());
                        warning("%.200s %.200s %.200s %.200s", arg_ra[0], arg_ra[1],
                                arg_ra[2], arg_ra[3]);
                        if (*rrderrors == SYMUX_MAXRRDERRORS) {
                            warning("maximum rrd errors reached - will stop reporting them");
                        }
                    }
                    rrd_clear_error();
                } else {
                    if (flag_debug == 1)
                        debug("%.200s %.200s %.200s %.200s", arg_ra[0], arg_ra[1],
                              arg_ra[2], arg_ra[3]);
                }
            }
            maxstringlen -= strlen(stringptr);
            stringptr += strlen(stringptr);
            snprintf(stringptr, maxstringlen, ";");
            maxstringlen -= strlen(stringptr);
            stringptr += strlen(stringptr);
        } else {
            debug("ignored unaccepted stream %.16s(%.16s) from %.20s", type2str(ps.type),
                  ((strlen(ps.arg) == 0) ? "0" : ps.arg), source->addr);
        }
    }
    /*
     * packet = parsed and in ascii in shared region -> copy to
     * clients
     */
    snprintf(stringptr, maxstringlen, "\n");
    stringptr += strlen(stringptr);
    shared_setlen(slot, (stringptr - stringbuf));
    debug("churnbuffer used: %d", (stringptr - stringbuf));
    master_permitread();
}

/*
 * Wait for traffic (symon reports from a source in sourclist | clients trying to connect
 * Returns the <source> and <packet>
 * Silently forks off clienthandlers
 */
void
wait_for_traffic(struct mux * mux, struct source ** source)
{
    fd_set allset, readset;
    unsigned int rrderrors;
    size_t is;
    int socksactive;
    int maxsock;

    if (SLIST_EMPTY(&mux->sol))
        fatal("no sources configured");

    rrderrors = 0;

    FD_ZERO(&allset);

    maxsock = 0;

    for (is = 0; is < mux->clientsocketcnt; is++) {
        FD_SET(mux->clientsocket[is], &readset);
        if (maxsock < mux->clientsocket[is])
            maxsock = mux->clientsocket[is];
    }

    for (is = 0; is < mux->symonsocketcnt; is++) {
        FD_SET(mux->symonsocket[is], &allset);
        if (maxsock < mux->symonsocket[is])
            maxsock = mux->symonsocket[is];
    }

    for (;;) {
        readset = allset;

        socksactive = select(maxsock + 1, &readset, NULL, NULL, NULL);
        if (socksactive == -1) {
            if (errno == EINTR)
                continue;

            fatal("select failed: %.200s", strerror(errno));
        }

        /* check tcp text listeners */
        for (is = 0; is < mux->clientsocketcnt && socksactive > 0; is++) {
            if (!FD_ISSET(mux->clientsocket[is], &readset))
                continue;

            spawn_client(mux->clientsocket[is]);
            socksactive--;
        }

        /* check udp symon listeners */
        for (is = 0; is < mux->symonsocketcnt && socksactive > 0; is++) {
            if (!FD_ISSET(mux->symonsocket[is], &readset))
                continue;

            if (recv_symon_packet(mux, mux->symonsocket[is], source))
                handlemessage(&mux->packet, *source, &rrderrors);

            socksactive--;
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
