// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include "trace_helpers.h"

#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	while (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (long) addr;
		syms[i].name = strdup(func);
		i++;
	}
	fclose(f);
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	return 0;
}

struct ksym *ksym_search(long key)
{
	int start = 0, end = sym_cnt;
	int result;

	/* kallsyms not loaded. return NULL */
	if (sym_cnt <= 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range. return _stext */
	return &syms[0];
}

long ksym_get_addr(const char *name)
{
	int i;

	for (i = 0; i < sym_cnt; i++) {
		if (strcmp(syms[i].name, name) == 0)
			return syms[i].addr;
	}

	return 0;
}

//static int page_size;
//static int page_cnt = 128;
static struct perf_event_mmap_page *header;

int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header, int page_cnt)
{
	void *base;
	int mmap_size;

	int page_size = sysconf(_SC_PAGESIZE);
	mmap_size = page_size * (page_cnt + 1);

	base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		printf("mmap err\n");
		return -1;
	}

	*header = base;
	return 0;
}

int perf_event_unmap(struct perf_event_mmap_page *header, size_t length) {
    return munmap(header, length);
}

int perf_event_mmap(int fd, int page_cnt)
{
	return perf_event_mmap_header(fd, &header, page_cnt);
}

/*
static int perf_event_poll(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	//return poll(&pfd, 1, 1000);
	return poll(&pfd, 1, 50);
}
*/

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
	struct perf_event_sample *e = (struct perf_event_sample *)hdr;
	perf_event_print_fn fn = private_data;
	int ret;

	if (e->header.type == PERF_RECORD_SAMPLE) {
		ret = fn(e->data, e->size);
		if (ret != LIBBPF_PERF_EVENT_CONT)
			return ret;
	} else if (e->header.type == PERF_RECORD_LOST) {
		struct {
			struct perf_event_header header;
			__u64 id;
			__u64 lost;
		} *lost = (void *) e;
		//fprintf(stderr,"lost %lld events\n", lost->lost);
	}
     /* else
        {
		fprintf(stderr,"unknown event type=%d size=%d\n",
		       e->header.type, e->header.size);
	}
         */

	return LIBBPF_PERF_EVENT_CONT;
}

/*
int perf_event_poller(int fd, perf_event_print_fn output_fn)
{
	enum bpf_perf_event_ret ret;
	void *buf = NULL;
	size_t len = 0;

	for (;;) {
		perf_event_poll(fd);
		ret = bpf_perf_event_read_simple(header, page_cnt * page_size,
						 page_size, &buf, &len,
						 bpf_perf_event_print,
						 output_fn);
		if (ret != LIBBPF_PERF_EVENT_CONT)
			break;
	}
	free(buf);

	return ret;
}
*/

int perf_event_poller_multi(int *fds, struct perf_event_mmap_page **headers,
			    int num_fds, perf_event_print_fn output_fn,
                            int *kill, int page_cnt)
{
    void *buf = NULL;
    enum bpf_perf_event_ret ret;
    struct epoll_event *pfds;
    size_t len = 0;
    int i;
    pfds = calloc(num_fds, sizeof(*pfds));
    if (!pfds)
        return LIBBPF_PERF_EVENT_ERROR;

    int efd = epoll_create1(0);
    if(efd < 0) {
        return -1;
    }

    for (i = 0; i < num_fds; i++) {

        pfds[i].data.fd = fds[i];
        pfds[i].events = EPOLLIN;

        if (epoll_ctl(efd, EPOLL_CTL_ADD, pfds[i].data.fd, &pfds[i])) {
            goto endpepm;
        }
    }

    int page_size = sysconf(_SC_PAGESIZE);
    for (;;) {
        int count = epoll_wait(efd, pfds, num_fds, 0);
        if(!count)
            continue;

        for (i = 0; i < num_fds; i++) {
            ret = bpf_perf_event_read_simple(headers[i],
                                        page_cnt * page_size,
                                        page_size, &buf, &len,
                                        bpf_perf_event_print,
                                        output_fn);
            if (ret != LIBBPF_PERF_EVENT_CONT)
                break;
        }

        if(*kill)
            break;
    }

endpepm:
    free(pfds);
    close(efd);
    return ret;

    /*
	enum bpf_perf_event_ret ret;
	struct pollfd *pfds;
	void *buf = NULL;
	size_t len = 0;
	int i;

	pfds = calloc(num_fds, sizeof(*pfds));
	if (!pfds)
		return LIBBPF_PERF_EVENT_ERROR;

	for (i = 0; i < num_fds; i++) {
		pfds[i].fd = fds[i];
		pfds[i].events = POLLIN;
	}

	for (;;) {
		poll(pfds, num_fds, 50);
		for (i = 0; i < num_fds; i++) {
	//		if (!pfds[i].revents)
	//			continue;

			ret = bpf_perf_event_read_simple(headers[i],
							 page_cnt * page_size,
							 page_size, &buf, &len,
							 bpf_perf_event_print,
							 output_fn);
			if (ret != LIBBPF_PERF_EVENT_CONT)
				break;

		}
                if(*kill)
                    break;
	}
	free(buf);
	free(pfds);

	return ret;
        */
}
