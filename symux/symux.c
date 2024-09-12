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
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "conf.h"
#include "data.h"
#include "error.h"
#include "limits.h"
#include "symux.h"
#include "symuxnet.h"
#include "net.h"
#include "readconf.h"
#include "xmalloc.h"

#include "platform.h"

__BEGIN_DECLS
void exithandler(int);
void signalhandler(int);
__END_DECLS

int flag_testconf = 0;
fd_set fdset;
int maxfd;

void
exithandler(int s)
{
    info("received signal %d - quitting", s);
    exit(EX_TEMPFAIL);
}
/*
 * symux is the receiver of symon performance measurements.
 *
 * The main goals symon hopes to accomplish is:
 * - to take fine grained measurements of system parameters
 * - with minimal performance impact
 * - in a secure way.
 *
 * Measuring system parameters (e.g. interfaces) sometimes means traversing
 * lists in kernel memory. Because of this the measurement of data has been
 * decoupled from the processing and storage of data. Storing the measured
 * information that symon provides is done by a second program, called symux.
 *
 * Symon can keep track of cpu, memory, disk and network interface
 * interactions. Symon was built specifically for OpenBSD.
 */
int
main(int argc, char *argv[])
{
    char *cfgfile;
    char *cfgpath = NULL;
    char *stringptr;
    int maxstringlen;
    struct muxlist mul;
    struct stream *stream;
    struct source *source;
    struct sourcelist *sol;
    struct mux *mux;
    FILE *f;
    int ch;
    int churnbuflen;
    int flag_list;
    int result;

    SLIST_INIT(&mul);

    /* reset flags */
    flag_debug = 0;
    flag_daemon = 0;
    flag_list = 0;

    cfgfile = SYMUX_CONFIG_FILE;

    while ((ch = getopt(argc, argv, "df:ltv")) != -1) {
        switch (ch) {
        case 'd':
            flag_debug = 1;
            break;

        case 'f':
            if (optarg && optarg[0] != '/') {
                /* cfg path needs to be absolute, we will be a daemon soon */
                cfgpath = xmalloc(MAX_PATH_LEN);
                if ((cfgpath = getcwd(cfgpath, MAX_PATH_LEN)) == NULL)
                    fatal("could not get working directory");

                maxstringlen = strlen(cfgpath) + 1 + strlen(optarg) + 1;
                cfgfile = xmalloc(maxstringlen);
                strncpy(cfgfile, cfgpath, maxstringlen - 1);
                stringptr = cfgfile + strlen(cfgpath);
                stringptr[0] = '/';
                stringptr++;
                strncpy(stringptr, optarg, maxstringlen - 1 - (stringptr - cfgfile));
                cfgfile[maxstringlen - 1] = '\0';

                xfree(cfgpath);
            } else
                cfgfile = xstrdup(optarg);
            break;

        case 'l':
            flag_list = 1;
            break;

        case 't':
            flag_testconf = 1;
            break;

        case 'v':
            info("symux version %s", SYMUX_VERSION);
	    /* FALLTHROUGH */
        default:
            info("usage: %s [-d] [-l] [-v] [-f cfgfile]", __progname);
            exit(EX_USAGE);
        }
    }

    if (flag_list == 1) {
        /* read configuration without file checks */
        result = read_config_file(&mul, cfgfile, 0);
        if (!result) {
            fatal("configuration contained errors; quitting");
        }

        mux = SLIST_FIRST(&mul);
        if (mux == NULL) {
            fatal("%s:%d: mux not found", __FILE__, __LINE__);
        }

        sol = &mux->sol;

        if (sol == NULL) {
            fatal("%s:%d: sourcelist not found", __FILE__, __LINE__);
        }

        SLIST_FOREACH(source, sol, sources) {
            if (! SLIST_EMPTY(&source->sl)) {
                SLIST_FOREACH(stream, &source->sl, streams) {
                    if (stream->file != NULL) {
                        info("%.200s", stream->file);
                    }
                }
            }
        }
        return (EX_OK);
    } else {
        /* read configuration file with file access checks */
        result = read_config_file(&mul, cfgfile, 1);
        if (!result) {
            fatal("configuration contained errors; quitting");
        }
    }

    if (flag_testconf) {
        info("%s: ok", cfgfile);
        exit(EX_OK);
    }

    /* ensure stdin is closed */
    close(STDIN_FILENO);

    setegid(getgid());
    setgid(getgid());

    if (flag_debug != 1) {
        if (daemon(0, 0) != 0)
            fatal("daemonize failed");

        flag_daemon = 1;

        /* record pid */
        f = fopen(SYMUX_PID_FILE, "w");
        if (f) {
            fprintf(f, "%u\n", (u_int) getpid());
            fclose(f);
        }
    }

    info("symux version %s", SYMUX_VERSION);

    if (flag_debug == 1)
        info("program id=%d", (u_int) getpid());

    mux = SLIST_FIRST(&mul);

    churnbuflen = strlen_sourcelist(&mux->sol);
    debug("size of churnbuffer = %d", churnbuflen);
    init_symux_packet(mux);

#ifdef HAS_UNVEIL
    SLIST_FOREACH(source, &mux->sol, sources) {
        if (! SLIST_EMPTY(&source->sl)) {
            SLIST_FOREACH(stream, &source->sl, streams) {
                if (stream->file != NULL) {
                    if (unveil(stream->file, "rw") == -1)
                        fatal("unveil %s: %.200s", stream->file, strerror(errno));
                }
            }
        }
    }

    if (unveil(SYMUX_PID_FILE, "w") == -1)
        fatal("unveil %s: %.200s", SYMUX_PID_FILE, strerror(errno));

    if (unveil(cfgfile, "r") == -1)
        fatal("unveil %s: %.200s", cfgfile, strerror(errno));

    if (unveil(NULL, NULL) == -1)
        fatal("disable unveil: %.200s", strerror(errno));
#endif

    /* catch signals */
    signal(SIGINT, exithandler);
    signal(SIGQUIT, exithandler);
    signal(SIGTERM, exithandler);
    signal(SIGTERM, exithandler);

    /* prepare crc32 */
    init_crc32();

    /* prepare sockets */
    mux->clientsocket = NULL;
    mux->clientsocketcnt = 0;
    mux->symonsocket = NULL;
    mux->symonsocketcnt = 0;
    if (create_listeners(&mux->clientsocket, &mux->clientsocketcnt, mux->addr,
            mux->port, SOCK_STREAM) == 0)
        fatal("no listeners could be created for incoming text client connections");

    if (create_listeners(&mux->symonsocket, &mux->symonsocketcnt, mux->addr,
            mux->port, SOCK_DGRAM) == 0)
        fatal("no listeners could be created for incoming symon traffic");

    /* main loop */
    wait_for_traffic(mux, &source);

    /* NOT REACHED */
    return (EX_SOFTWARE);
}
