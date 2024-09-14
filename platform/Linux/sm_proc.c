/*
 * Copyright (c) 2024 Tim Kuijsten
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

/*
 * Get process statistics from kernel and return them in symon_buf as
 *
 * number of processes : user microsec : system microsec :
 * total microsec : procsizes : resident segment sizes
 *
 * Note: user and system microsec are of more coarse granularity than total
 * microsec.
 */

#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conf.h"
#include "error.h"
#include "symon.h"
#include "xmalloc.h"

static int epoch;
static DIR *procfd;

/*
 * Create a list of word sized structures that contain the prefix of the command
 * to look for and the index in the streams array of the corresponding stream.
 * If the command fits in prefix, it is NUL terminated, otherwise not. The full
 * command is always in st->arg.
 * Maintain a separate list of stream pointers so that many commands can be
 * cramped into a cache line which is used with a binary search. The number of
 * "cmds" and "streams" must be equal.
 */
struct cmd2stream {
    /* Use one byte for stream index. */
    #define SM_PROC_CMDPREFIXLEN (sizeof(char *) - 1)
    char prefix[SM_PROC_CMDPREFIXLEN];   /* command prefix */
    uint8_t streamidx;
};
static struct stream **streams;
static struct cmd2stream *cmds;
static int cmdstreamcnt;
static char *proc_buf;
static size_t proc_bufsz;

static int
cmp(const void *a, const void *b)
{
    return strncmp(((const struct cmd2stream *)a)->prefix,
        ((const struct cmd2stream *)b)->prefix, SM_PROC_CMDPREFIXLEN);
}

/*
 * Search for the first stream that matches cmd.
 * Note: cmd must be NUL terminated.
 */
static int
matchcmd(const void *cmd, const void *c2s)
{
    int r;

    /*
     * For long cmds that don't fit in the prefix we need to compare a match
     * with the full argument saved in st->arg.
     */

    r = strncmp((const char *)cmd, ((const struct cmd2stream *)c2s)->prefix, SM_PROC_CMDPREFIXLEN);
    if (r != 0)
        return r;

    if (((const struct cmd2stream *)c2s)->prefix[SM_PROC_CMDPREFIXLEN - 1] == '\0') {
        /* command prefix is the complete command */
        return r;
    }

    /* command prefix is really just a prefix, compare the remaining characters */
    return strcmp(&((const char *)cmd)[SM_PROC_CMDPREFIXLEN],
        &streams[((const struct cmd2stream *)c2s)->streamidx]->arg[SM_PROC_CMDPREFIXLEN]);
}

void
privinit_proc(struct stream *st)
{
    /* EMPTY */
}

void
init_proc(struct stream *st)
{
    /* init once */
    if (procfd == NULL)
        if ((procfd = opendir("/proc")) == NULL)
            fatal("proc(%s) cannot open /proc: %s", st->arg, strerror(errno));

    if (bsearch(st->arg, cmds, cmdstreamcnt, sizeof *cmds, matchcmd) != NULL)
        fatal("duplicate proc(%s) configured", st->arg);

    memset(&st->parg.proc, 0x00, sizeof st->parg.proc);

    cmdstreamcnt++;
    streams = xreallocarray(streams, cmdstreamcnt, sizeof *streams);
    streams[cmdstreamcnt-1] = st;
    cmds = xreallocarray(cmds, cmdstreamcnt, sizeof *cmds);
    strncpy(cmds[cmdstreamcnt-1].prefix, st->arg, SM_PROC_CMDPREFIXLEN);
    cmds[cmdstreamcnt-1].streamidx = cmdstreamcnt-1;
    qsort(cmds, cmdstreamcnt, sizeof *cmds, cmp);

    if (proc_buf == NULL) {
        proc_bufsz = SYMON_MAX_OBJSIZE;
        proc_buf = xmalloc(proc_bufsz);
    }

    info("started module proc(%s)", st->arg);
}

static char buf20[20];
static char buf1024[1024];

void
gets_proc(void)
{
    struct cmd2stream *c2s;
    struct stream *st;
    struct usir *cm;
    struct dirent *dirent;
    uint64_t utime, stime;
    char *cmd;
    ssize_t r;
    int i, fd;

    epoch++;

    rewinddir(procfd);
    for (;;) {
next:
        errno = 0;
        dirent = readdir(procfd);
        if (dirent == NULL) {
            if (errno != 0)
                warning("gets_proc %s", strerror(errno));
            break;
        }

        /* filter out pids */
        for (i = 0; dirent->d_name[i] != '\0'; i++)
            if (dirent->d_name[i] < '0' || dirent->d_name[i] > '9')
                goto next;

        r = snprintf(buf20, sizeof buf20, "/proc/%s/exe", dirent->d_name);
        if (r < 0) {
            warning("snprintf failed on %s", dirent->d_name);
            continue;
        }
        if ((size_t)r >= sizeof buf20) {
            warning("file name too long: %s", dirent->d_name);
            continue;
        }
        r = readlink(buf20, buf1024, sizeof buf1024);
        if (r < 0 || (size_t)r >= sizeof buf1024) {
            if (errno != EACCES && errno != ENOENT)
                warning("exe symlink %s failed: %s", buf20, strerror(errno));
            continue;
        }
        buf1024[r] = '\0';

        cmd = strrchr(buf1024, '/');
        if (cmd == NULL)
            continue;

        cmd++;

        c2s = bsearch(cmd, cmds, cmdstreamcnt, sizeof *cmds, matchcmd);
        if (c2s == NULL)
            continue;

        st = streams[c2s->streamidx];

        r = snprintf(buf20, sizeof buf20, "/proc/%s/stat", dirent->d_name);
        if (r < 0) {
            warning("snprintf failed on %s", dirent->d_name);
            continue;
        }
        if ((size_t)r >= sizeof buf20) {
            warning("file name too long: %s", dirent->d_name);
            continue;
        }
        fd = open(buf20, O_RDONLY);
        if (fd == -1) {
            warning("could not open %s: %s", buf20, strerror(errno));
            continue;
        }
        r = read(fd, proc_buf, proc_bufsz - 1);
        if (r == -1) {
            warning("could not open %s: %s", buf20, strerror(errno));
            close(fd);
            fd = -1;
            continue;
        }
        close(fd);
        fd = -1;

        proc_buf[r] = '\0';

        if (epoch % 2 == 0) {
            cm = &st->parg.proc.m1;
        } else {
            cm = &st->parg.proc.m2;
        }

        if (st->parg.proc.epoch < epoch) {
            if (st->parg.proc.epoch < epoch - 1)
                warning("%s epoch skipped %d < %d", st->arg, st->parg.proc.epoch, epoch);

            memset(cm, 0x00, sizeof *cm);

            st->parg.proc.cpu_pcti     = 0;
            st->parg.proc.cnt          = 0;
            st->parg.proc.mem_procsize = 0;
            st->parg.proc.mem_rss      = 0;
            st->parg.proc.epoch        = epoch;
        }


        /* cpu usage - percentage since last measurement */
        /* TODO */
        //st->parg.proc.cpu_pcti += pctdouble(pp->p_pctcpu) * 100.0;

        // see proc_pid_stat(5)
        if (sscanf(proc_buf, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
                "%lu %lu "
                "%*d %*d %*d %*d %*d %*d %*u "
                "%lu %ld ",
                &utime,
                &stime, 
                &st->parg.proc.mem_procsize,
                &st->parg.proc.mem_rss) != 4) {
            warning("%s: could not get proc stats", cmd);
            continue;
        }

        /* TODO use pagesize */
        st->parg.proc.mem_rss *= 4096;

        /* convert to usec */
        /* TODO use sysconf(_SC_CLK_TCK) */
        cm->utime_usec += utime * 1000000 / 100;
        cm->stime_usec += stime * 1000000 / 100;
        cm->rtime_usec += (utime + stime) * 1000000 / 100;

        st->parg.proc.cnt++;
    }
}

int
get_proc(char *symon_buf, int maxlen, struct stream *st)
{
    struct usir *cm, *pm;
    uint32_t utime_diff, stime_diff, rtime_diff;

    /*
     * Set current and previous measurement. We're alternating depending on the
     * epoch.
     */
    if (epoch % 2 == 0) {
        cm = &st->parg.proc.m1;
        pm = &st->parg.proc.m2;
    } else {
        cm = &st->parg.proc.m2;
        pm = &st->parg.proc.m1;
    }

    /* skip first measurement since we want to submit a diff */
    if (epoch <= 1)
        return 0;

    /* nothing measured for this process in this round */
    if (st->parg.proc.epoch != epoch)
        return 0;

    /*
     * New total can be less if processes die, leave diff at 0 if this is the
     * case.
     */
    utime_diff = stime_diff = rtime_diff = 0;

    if (cm->utime_usec > pm->utime_usec)
        utime_diff = cm->utime_usec - pm->utime_usec;

    if (cm->stime_usec > pm->stime_usec)
        stime_diff = cm->stime_usec - pm->stime_usec;

    if (cm->rtime_usec > pm->rtime_usec)
        rtime_diff = cm->rtime_usec - pm->rtime_usec;

    return snpack(symon_buf, maxlen, st->arg, MT_PROC,
                  st->parg.proc.cnt,
                  utime_diff,
                  stime_diff,
                  rtime_diff,
                  st->parg.proc.cpu_pcti,
                  st->parg.proc.mem_procsize,
                  st->parg.proc.mem_rss);
}
