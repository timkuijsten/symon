#ifndef _CONF_OPENBSD_H
#define _CONF_OPENBSD_H

#include "conf.h"

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/select.h> /* fd_set */
#include <sys/socket.h>
#include <sys/sched.h>
#include <sys/syslimits.h>
#include <time.h>
#include <net/if.h>

#include "sylimits.h"

#define SYMON_USER      "_symon"
#define SEM_ARGS        (SEM_A|SEM_R)
#define SA_LEN(x)       ((x)->sa_len)
#define SS_LEN(x)       ((x)->ss_len)

#define MAX_PATH_LEN PATH_MAX

struct usir {
    uint64_t utime_usec; /* user */
    uint64_t stime_usec; /* sys  */
    uint64_t rtime_usec; /* real */
};

union stream_parg {
    struct {
        long time1[CPUSTATES];
        int64_t time2[CPUSTATES];
        int64_t old[CPUSTATES];
        int64_t diff[CPUSTATES];
        int64_t states[CPUSTATES];
        int mib[3];
        int miblen;
    } cp;
    struct {
        char rawdev[SYMON_DFNAMESIZE];
    } df;
    struct ifreq ifr;
    struct {
        int mib[5];
    } sn;
    int smart;
    struct {
        /* measurement 1 and 2 used in alternate fashion */
        struct usir m1;
        struct usir m2;
        double cpu_pcti;
        int cnt;    /* number of processes */
        int epoch;
        uint32_t mem_procsize; /* text, data and stack in bytes */
        uint32_t mem_rss;
    } proc;
};

#endif
