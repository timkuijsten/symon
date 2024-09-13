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
handlemessage(struct symonpacket *packet, struct source *source)
{
    int maxstringlen;
    int offset;
    char *stringptr;
    char *arg_ra[4];
    char stringbuf[8096];
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
    maxstringlen = sizeof stringbuf;
    timestamp = (time_t) packet->header.timestamp;

    stringptr = stringbuf;

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
                    warning("rrd_update:%.200s", rrd_get_error());
                    warning("%.200s %.200s %.200s %.200s", arg_ra[0], arg_ra[1],
                            arg_ra[2], arg_ra[3]);
                    rrd_clear_error();
                } else {
                    if (flag_debug == 1)
                        debug("%.200s %.200s %.200s %.200s", arg_ra[0], arg_ra[1],
                              arg_ra[2], arg_ra[3]);
                }
            }
        } else {
            debug("ignored unaccepted stream %.16s(%.16s) from %.20s", type2str(ps.type),
                  ((strlen(ps.arg) == 0) ? "0" : ps.arg), source->addr);
        }
    }
    /*
     * packet = parsed and in ascii in shared region -> copy to
     * clients
     */
    debug("churnbuffer used: %d", (stringptr - stringbuf));
}

/*
 * Receive data from a connected socket and try to parse a packet.
 * Returns 1 on success, 0 on partial read, -1 on error or peer disconnect.
 */
static int
recv_symon_packet_from_client(struct source *client)
{
    ssize_t n;
    uint32_t crc;

    n = read(client->sock,
        client->packet.data + client->received,
        client->packet.size - client->received);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;

        warning("%s: read failed: %.200s", client->addr, strerror(errno));
        return -1;
    }

    if (n == 0) {
        info("%s: disconnected", client->addr);
        return -1;
    }

    client->received += n;

    if (client->received < client->packet.size) /* partial read */
        return 0;

    /* if we only have a header, or even less, wait for more */
    if (client->received <= SYMON_HEADERSZ)
        return 0;

    client->packet.offset = getheader(client->packet.data, &client->packet.header);
    if (client->packet.header.length > client->packet.size) {
        warning("%s: received oversized packet; client and server have "
            "different stream configurations", client->addr);
        return -1;
    }

    if (client->packet.header.length > client->received) {
        info("partial packet: received %d bytes, packet length %d",
            client->received, client->packet.header.length);
        return 0; /* wait for more */
    }

    /* crc's are calculated with the crc field set to 0 */
    crc = client->packet.header.crc;
    client->packet.header.crc = 0;
    setheader(client->packet.data, &client->packet.header);
    crc ^= crc32(client->packet.data, client->packet.header.length);
    if (crc != 0) {
        warning("%s: crc mismatch", client->addr);
        return -1;
    }

    if (client->packet.header.symon_version > SYMON_PACKET_VER) {
        warning("%s: ignored packet with unsupported version: %d", client->addr,
            client->packet.header.symon_version);
        client->received -= client->packet.header.length;
        memmove(client->packet.data,
            &client->packet.data[client->packet.header.length],
            client->received);
        return 0;
    }

    if (flag_debug)
        debug("%s: good data received", client->addr);

    handlemessage(&client->packet, client);
    client->received -= client->packet.header.length;
    memmove(client->packet.data,
        &client->packet.data[client->packet.header.length], client->received);
    return 1;
}

/*
 * Wait for traffic (symon reports from a source in sourclist | clients trying to connect
 * Returns the <source> and <packet>
 * Silently forks off clienthandlers
 */
void
wait_for_traffic(struct mux * mux, struct source ** source)
{
    struct sockaddr_storage peername;
    struct source *client;
    fd_set allset, readset;
    socklen_t len;
    size_t is;
    int i, r, s, type;
    int socksactive;
    int maxsock;

    if (SLIST_EMPTY(&mux->sol))
        fatal("no sources configured");

    FD_ZERO(&allset);

    maxsock = 0;

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

        /* check connected symon tcp clients */
        SLIST_FOREACH(client, &mux->sol, sources) {
            if (client->sock < 0 || !FD_ISSET(client->sock, &readset))
                continue;

            if (recv_symon_packet_from_client(client) == -1) {
                info("%s: closing fd %d", client->addr, client->sock);
                if (client->received > 0)
                    warning("discarding %d bytes received", client->received);
                close(client->sock);
                FD_CLR(client->sock, &allset);
                if (client->sock == maxsock) {
                    for (i = client->sock - 1; i >= 0; i--) {
                        if (FD_ISSET(i, &allset)) {
                            maxsock = i;
                            break;
                        }
                    }
                }
                client->sock = -1;
                client->received = 0;
            }

            socksactive--;
            if (socksactive == 0)
                break;
        }

        /* check udp/tcp symon listeners */
        for (is = 0; is < mux->symonsocketcnt && socksactive > 0; is++) {
            if (mux->symonsocket[is] < 0 || !FD_ISSET(mux->symonsocket[is], &readset))
                continue;

            socksactive--;

            len = sizeof len;
            if (getsockopt(mux->symonsocket[is], SOL_SOCKET, SO_TYPE, &type, &len) == -1)
                fatal("could not obtain socket info: %.200s", strerror(errno));

            if (type == SOCK_DGRAM) {
                if (recv_symon_packet(mux, mux->symonsocket[is], source))
                    handlemessage(&mux->packet, *source);

                continue;
            }

            /* handle new connection */
            len = sizeof peername;
            s = accept(mux->symonsocket[is], (struct sockaddr *)&peername, &len);
            if (s == -1) {
                warning("accept failed: %.200s", strerror(errno));
                continue;
            }

            client = find_source_sockaddr(&mux->sol, (struct sockaddr *)&peername);
            get_numeric_name(&peername);
            if (client == NULL) {
                debug("closing connection with unconfigured source: %.200s:%.200s",
                    res_host, res_service);
                close(s);
                continue;
            }

            info("%s: connected from %s:%s", client->addr, res_host,
                res_service);

            r = fcntl(s, F_GETFD, 0);
            r = fcntl(s, F_SETFD, r | O_NONBLOCK);
            if (r == -1)
                fatal("%s: could not set client connection to non-blocking: %.200s",
                    client->addr, strerror(errno));

            if (client->received > 0)
                warning("discarding %d bytes received on previous connection",
                    client->received);

            close(client->sock);
            FD_CLR(client->sock, &allset);
            FD_SET(s, &allset);
            client->sock = s;
            client->received = 0;
            if (s > maxsock)
                maxsock = s;

            client->sockaddr = peername;
            client->sockaddrlen = len;
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
