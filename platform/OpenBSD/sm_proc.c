/*
 * Copyright (c) 2001-2012 Willem Dijkstra
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

/*
 * Get process statistics from kernel and return them in symon_buf as
 *
 * number of processes : user microsec : system microsec :
 * total microsec : procsizes : resident segment sizes
 *
 * Note: user and system microsec are of more coarse granularity than total
 * microsec.
 */

#include "conf.h"

#include <sys/param.h>
#include <sys/sysctl.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "symon.h"
#include "xmalloc.h"

#define pagetob(size) (((u_int32_t)size) << proc_pageshift)

/* Globals for this module start with proc_ */
static struct kinfo_proc *proc_ps = NULL;
static int proc_max = 0;
static int proc_cur = 0;
static int proc_pageshift;
static int proc_pagesize;
static int proc_fscale;
static int epoch;

/* get scale factor cpu percentage counter */
typedef long pctcpu;
#define pctdouble(p) ((double)(p) / proc_fscale)

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
gets_proc(void)
{
    struct kinfo_proc *pp;
    struct cmd2stream *c2s;
    struct stream *st;
    struct usir *cm;
    int i, mib[6];
    int procs;
    size_t size;

    epoch++;

    /* how much memory is needed */
    mib[0] = CTL_KERN;
    mib[1] = KERN_NPROCS;
    size = sizeof(procs);
    if (sysctl(mib, 2, &procs, &size, NULL, 0) < 0) {
        fatal("%s:%d: sysctl failed: can't get kern.nproc",
              __FILE__, __LINE__);
    }

    /* increase buffers if necessary */
    if (procs > proc_max) {
        proc_max = (procs * 5) / 4;

        if (proc_max > SYMON_MAX_DOBJECTS) {
            fatal("%s:%d: dynamic object limit (%d) exceeded for kinfo_proc structures",
                  __FILE__, __LINE__, SYMON_MAX_DOBJECTS);
        }

        proc_ps = xrealloc(proc_ps, proc_max * sizeof(struct kinfo_proc));
    }

    /* read data in anger */
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    mib[3] = 0;
    mib[4] = sizeof(struct kinfo_proc);
    mib[5] = proc_max;
    size = proc_max * sizeof(struct kinfo_proc);
    if (sysctl(mib, 6, proc_ps, &size, NULL, 0) < 0) {
        warning("proc probe cannot get processes");
        proc_cur = 0;
        return;
    }

    if (size % sizeof(struct kinfo_proc) != 0) {
        warning("proc size mismatch: got %d bytes, not dividable by sizeof(kinfo_proc) %d",
                size, sizeof(struct kinfo_proc));
        proc_cur = 0;
    } else {
        proc_cur = size / sizeof(struct kinfo_proc);
    }

    for (pp = proc_ps, i = 0; i < proc_cur; pp++, i++) {
        c2s = bsearch(pp->p_comm, cmds, cmdstreamcnt, sizeof *cmds, matchcmd);
        if (c2s == NULL)
            continue;

        st = streams[c2s->streamidx];

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

        cm->utime_usec += pp->p_uutime_sec * 1000000LLU + pp->p_uutime_usec;
        cm->stime_usec += pp->p_ustime_sec * 1000000LLU + pp->p_ustime_usec;
        cm->rtime_usec += pp->p_rtime_sec  * 1000000LLU + pp->p_rtime_usec;

        /* cpu usage - percentage since last measurement */
        st->parg.proc.cpu_pcti += pctdouble(pp->p_pctcpu) * 100.0;

        /* memory size - shared pages are counted multiple times */
        st->parg.proc.mem_procsize += pagetob(pp->p_vm_tsize + /* text pages */
            pp->p_vm_dsize +                                   /* data */
            pp->p_vm_ssize);                                   /* stack */
        st->parg.proc.mem_rss += pagetob(pp->p_vm_rssize);     /* rss  */
        st->parg.proc.cnt++;
    }
}

void
privinit_proc(struct stream *st)
{
    /* EMPTY */
}

void
init_proc(struct stream *st)
{
    int mib[2];
    size_t size;

    mib[0] = CTL_KERN;
    mib[1] = KERN_FSCALE;
    size = sizeof(proc_fscale);
    if (sysctl(mib, 2, &proc_fscale, &size, NULL, 0) == -1)
        fatal("%s:%d: KERN_FSCALE failed", __FILE__, __LINE__);

    /* get pagesize */
    proc_pagesize = sysconf(_SC_PAGESIZE);
    proc_pageshift = 0;
    while (proc_pagesize > 1) {
        proc_pageshift++;
        proc_pagesize >>= 1;
    }

    if (bsearch(st->arg, cmds, cmdstreamcnt, sizeof *cmds, matchcmd) != NULL)
        fatal("duplicate proc(%.200s) configured", st->arg);

    memset(&st->parg.proc, 0x00, sizeof st->parg.proc);

    cmdstreamcnt++;
    streams = xreallocarray(streams, cmdstreamcnt, sizeof *streams);
    streams[cmdstreamcnt-1] = st;
    cmds = xreallocarray(cmds, cmdstreamcnt, sizeof *cmds);
    strncpy(cmds[cmdstreamcnt-1].prefix, st->arg, SM_PROC_CMDPREFIXLEN);
    cmds[cmdstreamcnt-1].streamidx = cmdstreamcnt-1;
    qsort(cmds, cmdstreamcnt, sizeof *cmds, cmp);
    //for (int i = 0; i < cmdstreamcnt; i++)
        //info("%.*s", SM_PROC_CMDPREFIXLEN, cmds[i].prefix);

    info("started module proc(%.200s)", st->arg);
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
